"""Static analysis of pickle streams. Nothing here ever unpickles.

Unpickling runs code: a pickle can name any importable callable (``GLOBAL``, ``STACK_GLOBAL``,
``INST``) and call it (``REDUCE``, ``NEWOBJ``, ``OBJ``, ``BUILD``). This module walks the opcode
stream, simulating only the stack and memo, to find out which callables a pickle would import.

The opcode table comes from ``pickletools``, but arguments are read here with explicit bounds:
``pickletools.genops`` would allocate whatever length a hostile header declares. Large payloads
(tensor bytes, long strings) are skipped by seeking, never read.

Classification is deliberately conservative:

* **dangerous**: modules and callables that give a shell, file or network access, code
  evaluation, attribute access or nested deserialisation (``os.system``, ``builtins.eval``,
  ``builtins.getattr``, ``torch.load``, ...), and any name with a dunder;
* **safe**: what PyTorch, NumPy and joblib need to rebuild tensors and arrays, plus plain
  containers, and whatever the policy adds;
* **unknown**: everything else. A class from a library you trust is still code that runs on load.
"""

import pickletools
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import IO

UNKNOWN = object()  # a stack value we do not track
MARK = object()

_LARGE = 1 << 16  # string arguments longer than this are skipped, not read
_LINE = 1 << 16  # newline-terminated arguments must be shorter than this
_MAX_OPS = 50_000_000
_MAX_STACK = 1_000_000
_MAX_MEMO = 10_000_000

_OPCODES = {op.code.encode("latin-1")[0]: op for op in pickletools.opcodes}
_MARK = pickletools.markobject
_SLICE = pickletools.stackslice
_STRING_OPS = {
    "UNICODE",
    "SHORT_BINUNICODE",
    "BINUNICODE",
    "BINUNICODE8",
    "STRING",
    "BINSTRING",
    "SHORT_BINSTRING",
}
_CALL_OPS = {"REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST"}


class PickleError(ValueError):
    pass


@dataclass
class PickleScan:
    globals: list[tuple[str, str]] = field(default_factory=list)  # (module, name), first seen
    dynamic_globals: int = 0  # STACK_GLOBAL or EXT* whose target could not be resolved
    opcodes: int = 0
    calls: int = 0
    persistent_ids: int = 0
    pickles: int = 0  # complete pickles (STOP reached)
    protocol: int | None = None
    error: str | None = None
    error_offset: int | None = None
    trailing_bytes: bool = False  # data after the last pickle (legacy PyTorch storages)

    @property
    def complete(self) -> bool:
        return self.error is None and self.pickles > 0


class _Stream:
    def __init__(self, stream: IO[bytes], size: int | None) -> None:
        self.stream = stream
        self.size = size

    def tell(self) -> int:
        return self.stream.tell()

    def read(self, n: int) -> bytes:
        data = self.stream.read(n)
        if len(data) != n:
            raise PickleError("truncated pickle")
        return data

    def skip(self, n: int) -> None:
        target = self.stream.tell() + n
        if self.size is not None and target > self.size:
            raise PickleError("argument runs past the end of the file")
        self.stream.seek(target)

    def line(self) -> bytes:
        data = self.stream.readline(_LINE)
        if not data.endswith(b"\n"):
            raise PickleError("unterminated or over-long line argument")
        return data[:-1]

    def peek_byte(self) -> int | None:
        position = self.stream.tell()
        data = self.stream.read(1)
        self.stream.seek(position)
        return data[0] if data else None


def _unquote(raw: bytes) -> str | None:
    """Value of a STRING argument ('...' or "..."), without evaluating it."""
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[:1] in (b"'", b'"'):
        body = raw[1:-1]
        if b"\\" not in body:
            return body.decode("latin-1")
    return None


def _read_arg(op: pickletools.OpcodeInfo, s: _Stream) -> object:
    """Read (or skip) an opcode's argument. Returns the value where it can matter."""
    arg = op.arg
    if arg is None:
        return None
    n = arg.n
    if arg.name == "stringnl_noescape_pair":
        module = s.line().decode("utf-8", "replace")
        name = s.line().decode("utf-8", "replace")
        return (module, name)
    if n == pickletools.UP_TO_NEWLINE:
        raw = s.line()
        if arg.name == "unicodestringnl":
            return raw.decode("raw_unicode_escape", "replace")
        if arg.name == "stringnl":
            return _unquote(raw)
        if arg.name == "decimalnl_short":
            return int(raw) if raw.isdigit() else raw
        return None
    if n >= 0:
        data = s.read(n)
        return (
            int.from_bytes(data, "little", signed=arg.name == "int4") if n in (1, 2, 4, 8) else None
        )
    width = {
        pickletools.TAKEN_FROM_ARGUMENT1: 1,
        pickletools.TAKEN_FROM_ARGUMENT4: 4,
        pickletools.TAKEN_FROM_ARGUMENT4U: 4,
        pickletools.TAKEN_FROM_ARGUMENT8U: 8,
    }[n]
    length = int.from_bytes(s.read(width), "little", signed=n == pickletools.TAKEN_FROM_ARGUMENT4)
    if length < 0:
        raise PickleError("negative argument length")
    if length > _LARGE or op.name not in _STRING_OPS:
        s.skip(length)
        return None
    data = s.read(length)
    if op.name in ("BINSTRING", "SHORT_BINSTRING"):
        return data.decode("latin-1")
    return data.decode("utf-8", "replace")


def scan(stream: IO[bytes], *, size: int | None = None, max_ops: int = _MAX_OPS) -> PickleScan:
    """Walk every pickle at the start of ``stream``. Never raises for bad input; see ``error``."""
    s = _Stream(stream, size)
    result = PickleScan()
    seen: set[tuple[str, str]] = set()

    def record(module: object, name: object) -> None:
        if isinstance(module, str) and isinstance(name, str):
            if (module, name) not in seen:
                seen.add((module, name))
                result.globals.append((module, name))
        else:
            result.dynamic_globals += 1

    stack: list[object] = []
    memo: dict[object, object] = {}

    def pop() -> object:
        if not stack:
            raise PickleError("stack underflow")
        return stack.pop()

    def pop_to_mark() -> None:
        while True:
            if pop() is MARK:
                return

    try:
        while True:
            offset = s.tell()
            code = s.stream.read(1)
            if not code:
                raise PickleError("missing STOP opcode")
            op = _OPCODES.get(code[0])
            if op is None:
                raise PickleError(f"unknown opcode 0x{code[0]:02x}")
            result.opcodes += 1
            if result.opcodes > max_ops:
                raise PickleError("too many opcodes")
            value = _read_arg(op, s)
            name = op.name

            if name in _CALL_OPS:
                result.calls += 1
            if name == "PROTO":
                result.protocol = result.protocol if result.protocol is not None else int(value)  # type: ignore[call-overload]
            elif name in ("PERSID", "BINPERSID"):
                result.persistent_ids += 1

            if name == "STOP":
                pop()
                result.pickles += 1
                stack.clear()
                memo.clear()
                following = s.peek_byte()
                if following is None:
                    return result
                if following != 0x80:  # only another protocol 2+ pickle may follow
                    result.trailing_bytes = True
                    return result
                continue
            if name == "MARK":
                stack.append(MARK)
            elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
                if not stack:
                    raise PickleError("PUT with an empty stack")
                memo[value] = stack[-1]
            elif name == "MEMOIZE":
                if not stack:
                    raise PickleError("MEMOIZE with an empty stack")
                memo[len(memo)] = stack[-1]
            elif name in ("GET", "BINGET", "LONG_BINGET"):
                if value not in memo:
                    raise PickleError(f"memo key {value!r} used before it was set")
                stack.append(memo[value])
            elif name == "DUP":
                if not stack:
                    raise PickleError("DUP with an empty stack")
                stack.append(stack[-1])
            elif name == "GLOBAL":
                assert isinstance(value, tuple)  # noqa: S101 - the GLOBAL argument reader
                record(value[0], value[1])
                stack.append(UNKNOWN)
            elif name == "INST":
                assert isinstance(value, tuple)  # noqa: S101 - the INST argument reader
                record(value[0], value[1])
                pop_to_mark()
                stack.append(UNKNOWN)
            elif name == "STACK_GLOBAL":
                name_value = pop()
                record(pop(), name_value)
                stack.append(UNKNOWN)
            elif name in ("EXT1", "EXT2", "EXT4"):
                result.dynamic_globals += 1  # resolved through the copyreg extension registry
                stack.append(UNKNOWN)
            elif name in _STRING_OPS:
                stack.append(value if isinstance(value, str) else UNKNOWN)
            elif name in ("FRAME", "PROTO"):
                pass
            else:
                before, after = op.stack_before, op.stack_after
                if _SLICE in before:
                    below = before.index(_MARK)
                    pop_to_mark()
                    for _ in range(below):
                        pop()
                else:
                    for _ in before:
                        pop()
                stack.extend(UNKNOWN for _ in after)
            if len(stack) > _MAX_STACK or len(memo) > _MAX_MEMO:
                raise PickleError("stack or memo is unreasonably large")
    except (PickleError, ValueError, TypeError) as exc:
        result.error = str(exc) or type(exc).__name__
        result.error_offset = offset
        return result


# --- Classification -----------------------------------------------------------------------------

DANGEROUS_MODULES = frozenset(
    {
        "os", "posix", "nt", "posixpath", "ntpath", "subprocess", "sys", "socket", "ssl",
        "shutil", "pty", "runpy", "importlib", "imp", "zipimport", "pkgutil", "site",
        "pickle", "_pickle", "cPickle", "dill", "cloudpickle", "marshal", "shelve", "dbm",
        "types", "ctypes", "_ctypes", "code", "codeop", "commands", "pdb", "bdb", "timeit",
        "trace", "profile", "cProfile", "webbrowser", "http", "urllib", "urllib2", "urllib3",
        "requests", "httpx", "aiohttp", "httplib", "ftplib", "smtplib", "telnetlib",
        "poplib", "imaplib", "nntplib", "xmlrpc", "asyncio", "multiprocessing", "threading",
        "_thread", "concurrent", "signal", "platform", "tempfile", "glob", "io", "_io",
        "fileinput", "pathlib", "sysconfig", "distutils", "setuptools", "pip", "venv",
        "ensurepip", "sqlite3", "jinja2", "yaml", "torch.hub", "torch.jit",
        "torch.utils.cpp_extension", "torch.package", "numpy.f2py", "numpy.distutils",
        "numpy.ctypeslib", "_posixsubprocess", "_winapi", "winreg", "msvcrt",
    }
)  # fmt: skip
DANGEROUS_BUILTINS = frozenset(
    {
        "eval", "exec", "execfile", "compile", "open", "file", "__import__", "getattr",
        "setattr", "delattr", "globals", "locals", "vars", "input", "raw_input",
        "breakpoint", "help", "exit", "quit", "apply", "reload", "memoryview",
    }
)  # fmt: skip
DANGEROUS_NAMES = frozenset(
    {
        "operator.attrgetter", "operator.methodcaller", "_operator.attrgetter",
        "_operator.methodcaller", "functools.partial", "functools.reduce",
        "_functools.partial", "_functools.reduce", "torch.load", "torch.serialization.load",
        "torch.storage._load_from_bytes", "numpy.load", "numpy.lib.npyio.load",
        "numpy.testing._private.utils.runstring", "pandas.read_pickle",
        "pandas.io.pickle.read_pickle", "joblib.load", "copyreg.__newobj__",
    }
)  # fmt: skip
SAFE_NAMES = frozenset(
    {
        "collections.OrderedDict", "collections.defaultdict", "collections.Counter",
        "_codecs.encode", "copyreg._reconstructor", "copy_reg._reconstructor",
        "torch._utils._rebuild_tensor", "torch._utils._rebuild_tensor_v2",
        "torch._utils._rebuild_tensor_v3", "torch._utils._rebuild_parameter",
        "torch._utils._rebuild_parameter_with_state", "torch._utils._rebuild_qtensor",
        "torch._utils._rebuild_sparse_tensor", "torch._utils._rebuild_meta_tensor_no_storage",
        "torch._utils._rebuild_wrapper_subclass", "torch._utils._rebuild_device_tensor_from_numpy",
        "torch._tensor._rebuild_from_type_v2", "torch.nn.parameter.Parameter", "torch.Size",
        "torch.device", "torch.storage.UntypedStorage", "torch.storage.TypedStorage",
        "torch.serialization._get_layout", "torch.Tensor",
        "numpy.core.multiarray._reconstruct", "numpy._core.multiarray._reconstruct",
        "numpy.core.multiarray.scalar", "numpy._core.multiarray.scalar", "numpy.ndarray",
        "numpy.dtype", "numpy.core.numeric._frombuffer", "numpy._core.numeric._frombuffer",
        "joblib.numpy_pickle.NumpyArrayWrapper",
    }
)  # fmt: skip
_SAFE_BUILTINS = frozenset(
    {
        "set", "frozenset", "slice", "range", "complex", "bytearray", "bytes", "tuple",
        "list", "dict", "int", "float", "str", "bool", "object",
    }
)  # fmt: skip
_SAFE_PATTERNS = (
    re.compile(r"^torch\.[A-Za-z0-9]+Storage$"),
    re.compile(
        r"^torch\.(float|bfloat|half|double|int|uint|bool|complex|cfloat|cdouble|long|short"
        r"|qint|quint|float8|chalf)[A-Za-z0-9_]*$"
    ),
    re.compile(
        r"^torch\.(contiguous_format|channels_last|channels_last_3d|preserve_format|strided"
        r"|sparse_coo|per_tensor_affine|per_channel_affine|per_tensor_symmetric"
        r"|per_channel_symmetric)$"
    ),
    re.compile(r"^numpy\.dtypes\.[A-Za-z0-9]+DType$"),
)


_TORCHSCRIPT_NAMES = frozenset(
    f"torch.jit._pickle.{n}"
    for n in (
        "build_intlist", "build_tensorlist", "build_doublelist", "build_boollist",
        "build_genericlist", "build_tensor_from_id", "restore_type_tag",
    )
)  # fmt: skip


def _within(module: str, modules: frozenset[str]) -> bool:
    parts = module.split(".")
    return any(".".join(parts[:i]) in modules for i in range(1, len(parts) + 1))


def classify(
    module: str, name: str, allowed: Iterable[str] = (), *, torchscript: bool = False
) -> str:
    """'dangerous', 'safe' or 'unknown' for one imported callable.

    ``allowed`` holds extra safe names from policy: ``module.name`` or ``module.*``.
    Dangerous always wins over allowed. ``torchscript`` is set for a pickle inside a torch
    archive: TorchScript's list builders and its ``__torch__`` classes (which name code in the
    archive, never an importable module) are expected there.
    """
    full = f"{module}.{name}"
    if (
        torchscript
        and "__" not in name
        and (full in _TORCHSCRIPT_NAMES or module == "__torch__" or module.startswith("__torch__."))
    ):
        return "safe"
    first = name.split(".", 1)[0]
    if "__" in name or "__" in module.replace("__builtin__", ""):
        return "dangerous"
    if _within(module, DANGEROUS_MODULES) or full in DANGEROUS_NAMES:
        return "dangerous"
    if module in ("builtins", "__builtin__") and first in DANGEROUS_BUILTINS:
        return "dangerous"
    if full in SAFE_NAMES or any(p.match(full) for p in _SAFE_PATTERNS):
        return "safe"
    if module in ("builtins", "__builtin__") and name in _SAFE_BUILTINS:
        return "safe"
    for pattern in allowed:
        if full == pattern or (pattern.endswith(".*") and full.startswith(pattern[:-1])):
            return "safe"
    return "unknown"
