"""Built-in rules for model packages, model formats, licences and upstream trust.

All of these are policy matters except ``model.provenance.checksum-mismatch``: content that does
not match the publisher's own checksum is a hash mismatch, and is final like the bundle's own
integrity checks.
"""

from superscrubber104.core.model import Severity
from superscrubber104.core.rules import RuleSpec

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO  # noqa: E741

_CONVERT = "Convert the model to safetensors in an isolated environment, and transfer that."


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    controls: tuple[str, ...],
    rationale: str,
    *,
    final: bool = False,
    remediation: str = "",
) -> RuleSpec:
    return RuleSpec(rule_id, "1", title, severity, controls, rationale, remediation, final)


FORMATS = (
    _rule(
        "model.format.code-capable",
        "Model or data file can run code when loaded",
        M,
        ("SI-3", "CM-7", "SR-10"),
        "Pickle-based formats (PyTorch .pt/.bin/.ckpt, .pkl, joblib, NumPy object arrays) and "
        "TorchScript execute code on load. Even with no dangerous import found, loading the file "
        "trusts whoever wrote it.",
        remediation=_CONVERT,
    ),
    _rule(
        "model.pickle.dangerous-import",
        "Pickle imports a dangerous callable",
        C,
        ("SI-3", "SR-10"),
        "The stream imports something that gives code execution, shell, file or network access, "
        "or nested deserialisation. Loading it runs that code.",
        remediation="Do not load this file. Obtain the model in safetensors from the publisher.",
    ),
    _rule(
        "model.pickle.unknown-import",
        "Pickle imports callables outside the known-safe set",
        H,
        ("SI-3", "SR-10"),
        "Classes outside what PyTorch and NumPy need to rebuild tensors run their own code on "
        "load. Trusted libraries can be added to the policy's 'pickle-globals' allowlist.",
        remediation=_CONVERT,
    ),
    _rule(
        "model.pickle.malformed",
        "Pickle stream could not be analysed to the end",
        H,
        ("SI-3", "SR-10"),
        "A stream that defeats static analysis may be crafted to; what follows the error was "
        "not checked.",
    ),
    _rule(
        "model.keras.lambda-layer",
        "Keras model contains a Lambda layer",
        C,
        ("SI-3", "SR-10"),
        "A Lambda layer stores Python bytecode that runs when the model is loaded.",
        remediation="Replace Lambda layers with built-in layers, or export to ONNX or safetensors.",
    ),
    _rule(
        "model.keras.custom-object",
        "Keras model needs custom classes",
        H,
        ("SI-3", "SR-10"),
        "Custom objects name code outside Keras that must be importable, and is run, at load.",
    ),
    _rule(
        "model.onnx.custom-op",
        "ONNX model uses custom operators",
        H,
        ("SR-10", "CM-7"),
        "Operators outside the ONNX standard and the common runtimes need a native operator "
        "library registered at load time.",
    ),
    _rule(
        "model.format.opaque",
        "Compiled model format cannot be inspected",
        I,
        ("SR-10",),
        "TensorRT, TFLite, Core ML, OpenVINO and SavedModel content is recorded but not "
        "inspected; it is taken on trust.",
    ),
    _rule(
        "model.format.executable",
        "Model is packaged as an executable program",
        H,
        ("SI-3", "CM-7"),
        "llamafile-style bundles run as a program; they need the same review as any executable.",
    ),
    _rule(
        "model.weights.malformed",
        "Weights file is malformed or truncated",
        H,
        ("SI-7", "SR-10"),
        "A header that does not match the data, gaps between tensors, or data past the end of "
        "the file mean the file is damaged, or carries content no loader reads.",
    ),
    _rule(
        "model.template.suspicious",
        "Chat template contains constructs templates do not need",
        H,
        ("SI-3", "SR-10"),
        "Dunder attributes, the attr filter, imports and file or process access are how template "
        "injection reaches code. Legitimate chat templates do not use them.",
    ),
    _rule(
        "model.template.hidden-characters",
        "Chat template contains invisible characters",
        M,
        ("SI-3", "SR-10"),
        "Zero-width, bidirectional and tag characters let a template carry text a reviewer "
        "cannot see.",
    ),
)

PACKAGES = (
    _rule(
        "model.package.file-missing",
        "A file the model package needs is missing",
        H,
        ("CM-8", "SI-7"),
        "Missing shards, external data, layers or code make the model unusable and invite "
        "carrying the missing piece across informally.",
    ),
    _rule(
        "model.package.file-unreferenced",
        "Weights file is not referenced by the package's index",
        L,
        ("CM-8",),
        "A loader never reads it; it may be left over from another version.",
    ),
    _rule(
        "model.package.index-mismatch",
        "Shard index does not match the shards",
        H,
        ("SI-7", "CM-8"),
        "The index names tensors or sizes the shard files do not contain.",
    ),
    _rule(
        "model.package.config-mismatch",
        "Model configuration does not match the weights",
        H,
        ("SI-7", "CM-6"),
        "Vocabulary size, hidden size or layer count disagree with the tensors: the package was "
        "assembled from different models.",
    ),
    _rule(
        "model.package.config-missing",
        "Model package has no config.json",
        M,
        ("CM-8",),
        "Transformers-style weights cannot be loaded without their configuration.",
    ),
    _rule(
        "model.package.tokenizer-missing",
        "Model package has no tokenizer",
        M,
        ("CM-8",),
        "A text model needs the exact tokenizer it was trained with.",
    ),
    _rule(
        "model.package.tokenizer-mismatch",
        "Tokenizer has more tokens than the model's vocabulary",
        H,
        ("SI-7",),
        "Token ids past the embedding table fail or read the wrong embeddings.",
    ),
    _rule(
        "model.package.card-missing",
        "Model package has no model card",
        L,
        ("CM-8", "SA-11"),
        "The card records intended use, limitations and training data.",
    ),
    _rule(
        "model.package.requirement-unmet",
        "Something the model needs is not in the delivery",
        M,
        ("CM-8",),
        "An adapter's base model, or a Modelfile's FROM model, must be in the bundle or already "
        "on the receiving side.",
    ),
    _rule(
        "model.package.path-escape",
        "Model refers to a file outside the delivery",
        H,
        ("AC-4", "SI-7"),
        "An absolute path or '..' makes the runtime read whatever is at that location on the host.",
    ),
    _rule(
        "model.remote-code.required",
        "Model requires trust_remote_code",
        H,
        ("SI-3", "CM-7", "SR-10"),
        "The model's own Python code is imported and run by the loader.",
        remediation="Prefer a model supported natively by the inference library. If approved, "
        "the code is reviewed and pinned by hash like any other source.",
    ),
    _rule(
        "model.remote-code.external",
        "Model code is fetched from another repository",
        H,
        ("SC-7", "SR-3", "SI-3"),
        "auto_map points at code in a different Hugging Face repository: it will not be there "
        "offline, and it is code nobody reviewed with this package.",
    ),
    _rule(
        "model.provenance.checksum-mismatch",
        "Content does not match the publisher's checksum",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "The file differs from what the publisher's record says was downloaded.",
        final=True,
    ),
    _rule(
        "model.allowlist.unapproved",
        "Model is not on the approved list",
        H,
        ("SR-3", "SR-11", "CM-11"),
        "Only approved models, pinned by identity or content, may cross.",
    ),
)

LICENCES = (
    _rule(
        "licence.denied",
        "Licence is not permitted by policy",
        H,
        ("CM-10",),
        "The licence terms are on the policy's deny list, or unknown licences are blocked.",
    ),
    _rule(
        "licence.approval-required",
        "Licence needs approval",
        M,
        ("CM-10",),
        "The licence's terms (custom model licences, copyleft) need a decision for this use.",
    ),
    _rule(
        "licence.unidentified",
        "Licence was declared but not identified",
        M,
        ("CM-10",),
        "A licence text or name is present but matches no known licence.",
    ),
    _rule(
        "licence.missing",
        "No licence information",
        M,
        ("CM-10",),
        "Without a licence there is no permission to use the component.",
    ),
    _rule(
        "licence.conflict",
        "Licence declarations disagree",
        M,
        ("CM-10",),
        "Different files declare different licences; all of them are evaluated together.",
    ),
)

TRUST = (
    _rule(
        "trust.upstream.insufficient",
        "Genuineness is not established as strongly as policy requires",
        H,
        ("SR-4", "SR-11"),
        "Policy sets a minimum upstream trust level for this kind of content (signature, pinned "
        "checksum, ...); the evidence found is weaker.",
    ),
    _rule(
        "request.content.unit-missing",
        "Declared unit did not form",
        H,
        ("CM-8", "CM-3"),
        "The transfer request declares a unit (for example a model package) that the content "
        "under its paths does not make up.",
    ),
)

MODEL_RULES = (*FORMATS, *PACKAGES, *LICENCES, *TRUST)
