"""Command-line entry point."""

import functools
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import ParamSpec

import click

from airlock import __version__
from airlock.analyzer import TOOL
from airlock.approvals import approve as run_approve
from airlock.core.errors import AirlockError, ConfigError
from airlock.core.model import Analysis, Stage
from airlock.core.policy import Policy, load_policy
from airlock.core.serde import to_data
from airlock.core.signing import (
    SigningKey,
    generate_key,
    load_signing_key,
    load_verify_key,
    save_key,
)
from airlock.ledger import Ledger
from airlock.model_inspect import inspect_paths
from airlock.model_summary import render_packages
from airlock.pack import pack as run_pack
from airlock.scanners import run_scanners
from airlock.session import EXIT_USAGE, Session, exit_code, utc_now
from airlock.summary import render
from airlock.verify import verify as run_verify

P = ParamSpec("P")
_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)
_PASSPHRASE = click.option(
    "--passphrase-env",
    metavar="VAR",
    help="Environment variable holding the private key's passphrase.",
)


def _reports_errors(command: Callable[P, None]) -> Callable[P, None]:
    """Turn expected failures (bad input, bad config) into a message and exit code 2."""

    @functools.wraps(command)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> None:
        try:
            command(*args, **kwargs)
        except AirlockError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(EXIT_USAGE)

    return wrapper


def _passphrase(variable: str | None) -> bytes | None:
    if variable is None:
        return None
    value = os.environ.get(variable)
    if not value:
        raise ConfigError(f"environment variable {variable} is not set")
    return value.encode("utf-8")


def _policy(path: Path | None) -> Policy:
    return load_policy(path) if path else Policy.default()


def _key(path: Path | None, variable: str | None) -> SigningKey | None:
    return load_signing_key(path, _passphrase(variable)) if path else None


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="airlock")
def main() -> None:
    """Prepare, inspect, sign and verify deliveries for transfer across an air gap."""


@main.command()
@click.option("-o", "--out", type=click.Path(file_okay=False, path_type=Path), default=Path())
@click.option("--name", default="signing", show_default=True, help="Base name of the key files.")
@click.option("--holder", default="CHANGE-ME", help="Who holds this key (for the policy snippet).")
@_PASSPHRASE
@_reports_errors
def keygen(out: Path, name: str, holder: str, passphrase_env: str | None) -> None:
    """Create an Ed25519 key pair: NAME.key (private) and NAME.pub."""
    out.mkdir(parents=True, exist_ok=True)
    key = generate_key()
    public = out / f"{name}.pub"
    passphrase = _passphrase(passphrase_env)
    save_key(key, out / f"{name}.key", public, passphrase)
    import hashlib

    pin = hashlib.sha256(public.read_bytes()).hexdigest()
    click.echo(f"key id: {key.key_id}")
    if passphrase is None:
        click.echo("warning: the private key is not encrypted; protect the file", err=True)
    click.echo("\nTo trust this key, add it to the receiving side's policy:\n")
    click.echo(
        "trust:\n  signers:\n"
        f'    - keyId: "{key.key_id}"\n'
        f"      publicKey: {public.name}\n"
        f'      sha256: "{pin}"\n'
        f"      holder: {holder}\n"
        "      roles: [pack]"
    )


@main.command()
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--out", required=True, type=click.Path(file_okay=False, path_type=Path))
@click.option("--key", required=True, type=_FILE, help="Private signing key.")
@click.option("--policy", type=_FILE, help="Policy file (default: built-in defaults).")
@click.option("--request", type=_FILE, help="Transfer request.")
@click.option("-v", "--verbose", is_flag=True, help="Also list allowed findings.")
@_PASSPHRASE
@_reports_errors
def pack(
    inputs: tuple[Path, ...],
    out: Path,
    key: Path,
    policy: Path | None,
    request: Path | None,
    verbose: bool,
    passphrase_env: str | None,
) -> None:
    """Inventory, inspect and sign INPUTS into a bundle.

    A single directory becomes the bundle root. Several inputs are each placed under their own
    name. A bundle with policy blockers is still signed (overriding them is for approvers and
    the receiving side) and exits 1. A bundle that is refused outright is not signed and
    exits 3.
    """
    signer = _key(key, passphrase_env)
    assert signer is not None  # noqa: S101
    result = run_pack(inputs, out, signer=signer, policy=_policy(policy), request_path=request)
    click.echo(render(result.assessment, verbose=verbose))
    click.echo(f"manifest: {result.manifest_digest}")
    if result.signed:
        click.echo(f"bundle:   {result.bundle} (signed by {signer.key_id})")
    else:
        click.echo(f"bundle:   {result.bundle} (NOT SIGNED: refused)")
    sys.exit(exit_code(result.assessment))


@main.command()
@click.argument("bundle", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--policy", type=_FILE, help="This side's policy (default: built-in defaults).")
@click.option("--pubkey", type=_FILE, help="Packer's public key, if the policy pins none.")
@click.option(
    "--state",
    type=click.Path(file_okay=False, path_type=Path),
    help="State directory holding the ledger of earlier imports.",
)
@click.option("--key", type=_FILE, help="Private key for signing the receipt and ledger entry.")
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    help="Where to write the assessment and receipt (default: under --state).",
)
@click.option("-v", "--verbose", is_flag=True, help="Also list allowed findings.")
@_PASSPHRASE
@_reports_errors
def verify(
    bundle: Path,
    policy: Path | None,
    pubkey: Path | None,
    state: Path | None,
    key: Path | None,
    out: Path | None,
    verbose: bool,
    passphrase_env: str | None,
) -> None:
    """Verify BUNDLE with this side's own policy, keys and checks.

    Exit codes: 0 accepted; 1 a policy blocker stands or approvals are outstanding (both can
    be cleared with 'airlock approve'); 2 usage or configuration error; 3 refused: an
    integrity or authenticity check failed, which nothing can override.
    """
    loaded = _policy(policy)
    if pubkey is None and not loaded.signers:
        raise ConfigError(
            "no trusted signer: pin one in the policy (trust.signers) or pass --pubkey"
        )
    result = run_verify(
        bundle,
        policy=loaded,
        pubkey=load_verify_key(pubkey) if pubkey else None,
        state=state,
        receipt_signer=_key(key, passphrase_env),
        out=out,
    )
    click.echo(render(result.assessment, verbose=verbose))
    for path in result.outputs:
        click.echo(f"wrote:    {path}")
    sys.exit(exit_code(result.assessment))


@main.command()
@click.argument("bundle", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--key", required=True, type=_FILE, help="The approver's private key.")
@click.option(
    "-f",
    "--finding",
    "findings",
    multiple=True,
    required=True,
    metavar="ID",
    help="Finding id, as shown in brackets by pack and verify. Repeatable.",
)
@click.option("-j", "--justification", required=True, help="Why this is acceptable. Signed.")
@click.option(
    "--assessment",
    type=_FILE,
    help="The assessment you reviewed (default: the packer's, inside the bundle). On the "
    "receiving side, pass this side's assessment.verify.json.",
)
@_PASSPHRASE
@_reports_errors
def approve(
    bundle: Path,
    key: Path,
    findings: tuple[str, ...],
    justification: str,
    assessment: Path | None,
    passphrase_env: str | None,
) -> None:
    """Sign an approval of findings in BUNDLE, with a written justification.

    Clears findings decided 'require-approval' and overrides policy blockers, once enough
    distinct approvers have signed. Integrity and authenticity failures cannot be approved.
    The packer cannot approve its own bundle. Whether an approval counts is decided by the
    verifying side's policy; run 'airlock verify' again to see.
    """
    signer = _key(key, passphrase_env)
    assert signer is not None  # noqa: S101
    approvals = run_approve(
        bundle,
        signer=signer,
        findings=findings,
        justification=justification,
        now=utc_now(),
        assessment_path=assessment,
    )
    for approval in approvals:
        click.echo(f"approved [{approval.finding}] as {signer.key_id}")


@main.group()
def ledger() -> None:
    """Maintain the receiving side's ledger of imports."""


@ledger.command("adjust-clock")
@click.option(
    "--state", required=True, type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.option("--reason", required=True, help="Why the clock was set back. Recorded and signed.")
@click.option("--key", type=_FILE, help="Private key for signing the ledger entry.")
@_PASSPHRASE
@_reports_errors
def adjust_clock(state: Path, reason: str, key: Path | None, passphrase_env: str | None) -> None:
    """Record that this system's clock was deliberately set back.

    'airlock verify' refuses imports while the clock is earlier than the ledger's latest entry,
    because age and ordering checks would be meaningless. If the clock was wrong earlier and has
    now been corrected, this records the correction as a signed ledger entry and lets imports
    resume. The adjustment and its reason are listed in the next import's assessment.
    """
    if not reason.strip():
        raise ConfigError("a reason is required")
    book = Ledger(state)
    problems = book.load(lambda _key_id: None, require_signed=False)
    damage = [p for p in problems if "untrusted key" not in p]
    if damage:
        raise ConfigError(
            "the ledger is damaged; restore it before adjusting: " + "; ".join(damage)
        )
    now, mark = utc_now(), book.high_water
    if mark is None or now >= mark:
        click.echo(f"the clock ({now.isoformat()}) is not behind the ledger; nothing recorded")
        return
    signer = _key(key, passphrase_env)
    book.adjust_clock(now=now, reason=reason.strip(), signer=signer)
    click.echo(f"ledger high-water mark was {mark.isoformat()}")
    click.echo(
        f"recorded clock adjustment to {now.isoformat()}" + ("" if signer else " (unsigned)")
    )


@main.group()
def plugins() -> None:
    """External scanners (ClamAV, Trivy) and feeds (CISA KEV)."""


@plugins.command("check")
@click.option("--policy", required=True, type=_FILE, help="The policy that configures them.")
@_reports_errors
def plugins_check(policy: Path) -> None:
    """Check every scanner the policy configures, without scanning anything.

    Finds each binary, compares it and its database with the pinned hashes, reads its version
    and the age of its database. Exit codes are those of 'airlock verify'.
    """
    loaded = _policy(policy)
    session = Session.start(loaded, utc_now())
    if not loaded.plugins:
        click.echo("The policy configures no plugins (see docs/scanners.md).")
    empty = Analysis.create(TOOL, [], [], [])
    statuses = run_scanners(session.ctx, [], empty, preflight_only=True)
    for status in statuses:
        state = "ready" if status.present and status.reason is None else "NOT USABLE"
        click.echo(f"{status.name:<8} {state}")
        for label, value in (
            ("version", status.version),
            ("database", status.data_version),
            (
                "age",
                f"{status.data_age_seconds // 3600} h"
                if status.data_age_seconds is not None
                else None,
            ),
            ("binary", status.binary_sha256 and f"sha256:{status.binary_sha256}"),
            ("pinned", None if status.pinned is None else ("yes" if status.pinned else "no")),
            ("reason", status.reason),
        ):
            if value:
                click.echo(f"         {label:<9}{value}")
    assessment = session.finish(
        Stage.INSPECT, manifest_digest=None, content_hashes={}, plugins=statuses
    )
    click.echo()
    click.echo(render(assessment))
    sys.exit(exit_code(assessment))


@main.group()
def model() -> None:
    """Inspect AI models."""


@model.command("inspect")
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--policy", type=_FILE, help="Policy file (default: built-in defaults).")
@click.option("--json", "as_json", is_flag=True, help="Print the records and findings as JSON.")
@click.option("-v", "--verbose", is_flag=True, help="Also list allowed findings.")
@_reports_errors
def model_inspect(
    inputs: tuple[Path, ...], policy: Path | None, as_json: bool, verbose: bool
) -> None:
    """Record and check the model packages in INPUTS, in place, without packing.

    Exit codes are those of 'airlock verify'.
    """
    result = inspect_paths(inputs, policy=_policy(policy))
    if as_json:
        document = {
            "units": [to_data(u) for u in result.analysis.units],
            "components": [to_data(c) for c in result.analysis.components],
            "assessment": to_data(result.assessment),
        }
        click.echo(json.dumps(document, indent=2, sort_keys=True))
    else:
        click.echo(render_packages(result.analysis.units))
        click.echo()
        click.echo(render(result.assessment, verbose=verbose))
    sys.exit(exit_code(result.assessment))
