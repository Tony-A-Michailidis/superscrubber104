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
from airlock.bundle import encode
from airlock.core.errors import AirlockError, ConfigError
from airlock.core.model import Analysis, Stage, Verdict
from airlock.core.policy import Policy, load_policy
from airlock.core.serde import to_data
from airlock.core.signing import (
    SigningKey,
    generate_key,
    load_signing_key,
    load_verify_key,
    save_key,
)
from airlock.core.yamlio import parse_size
from airlock.eval_run import run_eval, write_results
from airlock.ledger import Ledger
from airlock.model_inspect import inspect_paths
from airlock.model_summary import render_packages
from airlock.offline_report import (
    offline_findings,
    offline_summary,
    recommended_configuration,
    render_offline,
)
from airlock.pack import pack as run_pack
from airlock.report import FORMATS, load_source
from airlock.report import render as render_report
from airlock.scanners import run_scanners
from airlock.session import (
    EXIT_BLOCKED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_USAGE,
    Session,
    exit_code,
    utc_now,
)
from airlock.stage import StageReport
from airlock.summary import render
from airlock.verify import verify as run_verify
from airlock.volumes import check_volume

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
@click.option(
    "--volume-size",
    help="Split the payload into volumes of this size for removable media (e.g. 25GB, 4GiB).",
)
@click.option(
    "--delta-from",
    type=click.Path(exists=True, path_type=Path),
    help="An earlier bundle (or its manifest.json): unchanged files are carried, not copied.",
)
@click.option("--link", is_flag=True, help="Hard-link files into the payload instead of copying.")
@click.option("-v", "--verbose", is_flag=True, help="Also list allowed findings.")
@_PASSPHRASE
@_reports_errors
def pack(
    inputs: tuple[Path, ...],
    out: Path,
    key: Path,
    policy: Path | None,
    request: Path | None,
    volume_size: str | None,
    delta_from: Path | None,
    link: bool,
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
    try:
        size = parse_size(volume_size) if volume_size else None
    except ValueError as exc:
        raise ConfigError(f"--volume-size: {exc}") from exc
    result = run_pack(
        inputs,
        out,
        signer=signer,
        policy=_policy(policy),
        request_path=request,
        volume_size=size,
        delta_from=delta_from,
        link=link,
    )
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
@click.option(
    "--volume",
    "volume_dirs",
    multiple=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="A medium holding volumes of this bundle (repeatable).",
)
@click.option(
    "--base",
    "bases",
    multiple=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="An accepted earlier bundle that this delta's carried files come from (repeatable).",
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
    volume_dirs: tuple[Path, ...],
    bases: tuple[Path, ...],
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
        volume_dirs=volume_dirs,
        bases=bases,
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


@main.command("offline-check")
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--policy", type=_FILE, help="Policy file (default: built-in defaults).")
@click.option("--corpus", multiple=True, help="Path glob of knowledge-base documents (repeatable).")
@click.option(
    "--json", "as_json", is_flag=True, help="Print the findings and configuration as JSON."
)
@_reports_errors
def offline_check(
    inputs: tuple[Path, ...], policy: Path | None, corpus: tuple[str, ...], as_json: bool
) -> None:
    """Report what INPUTS will try to download, report or call once disconnected.

    Ends with the configuration to set on the high side. Exit codes are those of
    'airlock verify', over the offline and runtime findings only.
    """
    result = inspect_paths(
        inputs,
        policy=_policy(policy),
        run_plugins=False,
        corpora=corpus,
        stage=Stage.OFFLINE_CHECK,
    )
    findings = offline_findings(result.assessment)
    summary = offline_summary(result.assessment)
    if as_json:
        environment, settings = recommended_configuration(findings)
        document = {
            "verdict": summary.verdict.value,
            "findings": [to_data(f) for f in findings],
            "recommended": {"environment": environment, "settings": settings},
        }
        click.echo(json.dumps(document, indent=2, sort_keys=True))
    else:
        click.echo(render_offline(result.assessment))
        click.echo(f"Verdict: {summary.verdict.value}")
    if summary.verdict is Verdict.REFUSED:
        sys.exit(EXIT_REFUSED)
    sys.exit(EXIT_OK if summary.verdict is Verdict.PASSED else EXIT_BLOCKED)


@main.group()
def volume() -> None:
    """Volumes of a multi-volume bundle, one medium at a time."""


@volume.command("check")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path))
@_reports_errors
def volume_check(directory: Path) -> None:
    """Check one volume against its own volume.json, without the rest of the bundle.

    For writing and hand-over of media. It is not verification: only 'airlock verify' checks
    the volumes against the signed index and manifest. Exits 3 if anything is wrong.
    """
    label, problems = check_volume(directory)
    click.echo(f"volume {label.number} of {label.count}: {len(label.pieces)} piece(s)")
    for problem in problems:
        click.echo(f"  {problem['problem']}: {problem['piece']}")
    click.echo("intact" if not problems else f"{len(problems)} problem(s)")
    sys.exit(EXIT_OK if not problems else EXIT_REFUSED)


@main.command("report")
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-f",
    "--format",
    "fmt",
    type=click.Choice(FORMATS),
    default="md",
    show_default=True,
    help="md and html for reviewers; json; cyclonedx (SBOM/ML-BOM); oscal (assessment results).",
)
@click.option("-o", "--out", type=click.Path(dir_okay=False, path_type=Path), help="Write here.")
@click.option("--policy", type=_FILE, help="Policy whose control catalogue to report against.")
@_reports_errors
def report(source: Path, fmt: str, out: Path | None, policy: Path | None) -> None:
    """Render a report from SOURCE: a bundle, an 'airlock verify' or 'model inspect' output
    directory, or an assessment file.

    A bundle holds the packing side's assessment; for this side's own, report on the directory
    'airlock verify --out' wrote.
    """
    catalog = _policy(policy).catalog() if policy else None
    text = render_report(load_source(source), fmt, catalog)
    if out is None:
        click.echo(text, nl=False)
    else:
        out.write_text(text, encoding="utf-8")
        click.echo(f"wrote:    {out}")


@main.group("eval")
def eval_group() -> None:
    """Behavioural verification: run pinned evaluation sets through a pinned local runtime."""


@eval_group.command("run")
@click.argument("evalset", type=_FILE)
@click.option("--model", "model_path", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--runtime", required=True, help="Name of a runtime under 'runtimes' in the policy.")
@click.option("--policy", required=True, type=_FILE, help="Policy that configures the runtime.")
@click.option("--reference", type=_FILE, help="Results from the other side to compare with.")
@click.option("--side", type=click.Choice(["low", "high"]), default="low", show_default=True)
@click.option("-o", "--out", type=click.Path(dir_okay=False, path_type=Path), help="Write results.")
@_reports_errors
def eval_run(
    evalset: Path,
    model_path: Path,
    runtime: str,
    policy: Path,
    reference: Path | None,
    side: str,
    out: Path | None,
) -> None:
    """Run EVALSET against the model at --model and record every output.

    On the low side, keep the results (--out) and deliver them with the model. On the high side,
    pass them as --reference: the set and model must be the same, and every output must match
    within the set's tolerance. Exit codes are those of 'airlock verify'.
    """
    run = run_eval(evalset, model_path, runtime, _policy(policy), reference=reference, side=side)
    if out is not None:
        write_results(out, run.results)
    cases = run.results.get("cases")
    count = len(cases) if isinstance(cases, list) else 0
    click.echo(f"{count} case(s) run on {runtime}")
    click.echo(render(run.assessment))
    sys.exit(exit_code(run.assessment))


@main.group()
def model() -> None:
    """Inspect AI models."""


@model.command("inspect")
@click.argument("inputs", nargs=-1, required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--policy", type=_FILE, help="Policy file (default: built-in defaults).")
@click.option("--json", "as_json", is_flag=True, help="Print the records and findings as JSON.")
@click.option(
    "--corpus",
    multiple=True,
    help="Path glob of documents a knowledge base will be built from (repeatable).",
)
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    help="Also write analysis.inspect.json and assessment.inspect.json here (for airlock report).",
)
@click.option("-v", "--verbose", is_flag=True, help="Also list allowed findings.")
@_reports_errors
def model_inspect(
    inputs: tuple[Path, ...],
    policy: Path | None,
    as_json: bool,
    corpus: tuple[str, ...],
    out: Path | None,
    verbose: bool,
) -> None:
    """Record and check the model packages in INPUTS, in place, without packing.

    Exit codes are those of 'airlock verify'.
    """
    result = inspect_paths(inputs, policy=_policy(policy), corpora=corpus)
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "analysis.inspect.json").write_bytes(encode(result.analysis))
        (out / "assessment.inspect.json").write_bytes(encode(result.assessment))
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


@main.group()
def patch() -> None:
    """Patch disconnected hosts: inventory (high side), plan (low side), confirm."""


@patch.command("inventory")
@click.option(
    "--root",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Root filesystem of the Linux host to inventory (default /).",
)
@click.option("--label", required=True, help="Name for this host in the plan (never the hostname).")
@click.option("--windows-hotfixes", type=_FILE, help="Get-HotFix output as JSON (Windows hosts).")
@click.option("--windows-product", help='Windows product name, e.g. "Windows Server 2022".')
@click.option("--windows-build", help="Windows OS build, e.g. 10.0.20348.2700.")
@click.option("--key", type=_FILE, help="Private key that signs the inventory (the receipt key).")
@click.option("--key-passphrase-env", help="Environment variable holding the key's passphrase.")
@click.option("-o", "--out", required=True, type=click.Path(dir_okay=False, path_type=Path))
@_reports_errors
def patch_inventory(
    root: Path | None,
    label: str,
    windows_hotfixes: Path | None,
    windows_product: str | None,
    windows_build: str | None,
    key: Path | None,
    key_passphrase_env: str | None,
    out: Path,
) -> None:
    """Record what is installed, to carry to the low side. Holds names and versions only."""
    from airlock.patch.inventory import collect, from_windows, sign
    from airlock.patch.inventory import encode as encode_inventory
    from airlock.session import utc_now

    now = utc_now()
    if windows_hotfixes is not None:
        if not windows_product or not windows_build:
            raise ConfigError("--windows-product and --windows-build go with --windows-hotfixes")
        inventory = from_windows(windows_hotfixes, windows_product, windows_build, label, now)
    else:
        inventory = collect(root or Path("/"), label, now)
    signer = _key(key, key_passphrase_env)
    data = sign(inventory, signer) if signer else encode(encode_inventory(inventory))
    out.write_bytes(data)
    click.echo(
        f"{len(inventory.packages)} "
        f"{'updates' if inventory.os.family == 'windows' else 'packages'} "
        f"on {inventory.os.id} {inventory.os.version_id}"
        f"{', signed' if signer else ', unsigned'} -> {out}"
    )


@patch.command("plan")
@click.option(
    "--inventory", "inventory_path", required=True, type=_FILE, help="The host's inventory."
)
@click.option(
    "--feed",
    "feeds",
    multiple=True,
    required=True,
    type=click.Path(exists=True, path_type=Path),
    help="Feed snapshot: OSV file/dir/zip, updateinfo.xml, MSRC CVRF JSON, KEV JSON (repeatable).",
)
@click.option("--policy", type=_FILE, help="Policy: pinned inventory keys and freshness.feeds.")
@click.option(
    "--cve", "cves", multiple=True, help="Emergency plan: only advisories fixing this CVE."
)
@click.option("--kev", "kev_only", is_flag=True, help="Emergency plan: only KEV-listed CVEs.")
@click.option("-o", "--out", required=True, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--markdown", "markdown_out", type=click.Path(dir_okay=False, path_type=Path))
@_reports_errors
def patch_plan(
    inventory_path: Path,
    feeds: tuple[Path, ...],
    policy: Path | None,
    cves: tuple[str, ...],
    kev_only: bool,
    out: Path,
    markdown_out: Path | None,
) -> None:
    """Match an inventory against offline feed snapshots. Exit 3 if a feed is stale."""
    from airlock.core.policy import KeyRole
    from airlock.feeds.readers import load_feeds
    from airlock.patch.inventory import load as load_inventory
    from airlock.patch.plan import markdown, plan
    from airlock.session import utc_now

    loaded = _policy(policy)
    keys = [s.load() for s in loaded.signers_with_role(KeyRole.RECEIPT)]
    inventory, signers = load_inventory(inventory_path, keys)
    if keys and not signers:
        raise ConfigError("the inventory is not signed by a receipt key the policy pins")
    result = plan(
        inventory,
        load_feeds(feeds),
        utc_now(),
        max_age=loaded.feed_max_age,
        cves=cves,
        kev_only=kev_only,
    )
    out.write_bytes(encode(result))
    if markdown_out is not None:
        markdown_out.write_text(markdown(result), encoding="utf-8")
    click.echo(
        f"{len(result.gaps)} advisories, {sum(g.kev for g in result.gaps)} on KEV, "
        f"{len(result.fetch)} packages to fetch -> {out}"
    )
    if result.stale_feeds:
        click.echo(f"stale or unreadable feeds: {', '.join(result.stale_feeds)}", err=True)
        sys.exit(3)


@patch.command("confirm")
@click.option("--plan", "plan_path", required=True, type=_FILE, help="The earlier plan.")
@click.option("--inventory", "inventory_path", required=True, type=_FILE, help="A fresh inventory.")
@click.option(
    "--feed", "feeds", multiple=True, required=True, type=click.Path(exists=True, path_type=Path)
)
@click.option("--policy", type=_FILE, help="Policy: pinned inventory keys.")
@_reports_errors
def patch_confirm(
    plan_path: Path, inventory_path: Path, feeds: tuple[Path, ...], policy: Path | None
) -> None:
    """Show which gaps of a plan are closed. Exit 2 while any remain open."""
    from airlock.core.policy import KeyRole
    from airlock.core.serde import from_data
    from airlock.feeds.readers import load_feeds
    from airlock.patch.inventory import load as load_inventory
    from airlock.patch.plan import PatchPlan, confirm
    from airlock.session import utc_now

    loaded = _policy(policy)
    keys = [s.load() for s in loaded.signers_with_role(KeyRole.RECEIPT)]
    inventory, signers = load_inventory(inventory_path, keys)
    if keys and not signers:
        raise ConfigError("the inventory is not signed by a receipt key the policy pins")
    previous = from_data(PatchPlan, json.loads(plan_path.read_bytes()))
    outcome = confirm(previous, inventory, load_feeds(feeds), utc_now())
    click.echo(json.dumps(outcome, indent=2))
    sys.exit(2 if outcome["open"] else 0)


def _targets(values: tuple[str, ...]) -> dict[str, Path]:
    targets: dict[str, Path] = {}
    for value in values:
        kind, eq, destination = value.partition("=")
        if not eq or not destination:
            raise ConfigError(f"--target takes KIND=DIRECTORY, not {value!r}")
        targets[kind.strip()] = Path(destination)
    return targets


_STAGE_OPTIONS = [
    click.option("--policy", required=True, type=_FILE, help="This side's policy."),
    click.option(
        "--state",
        required=True,
        type=click.Path(file_okay=False, path_type=Path),
        help="This side's state directory: the bundle must have been accepted there.",
    ),
    click.option(
        "--target",
        "target_values",
        multiple=True,
        required=True,
        help="KIND=DIRECTORY, KIND one of files, models, pypi, npm, dnf, apt, oci, windows.",
    ),
    click.option("--key", type=_FILE, help="Private key that signs the ledger's stage event."),
    click.option("--key-passphrase-env", help="Environment variable holding the key's passphrase."),
    click.option(
        "--volume",
        "volume_dirs",
        multiple=True,
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        help="Medium holding volumes of a multi-volume bundle (repeatable).",
    ),
    click.option(
        "--base",
        "bases",
        multiple=True,
        type=click.Path(exists=True, file_okay=False, path_type=Path),
        help="Accepted bundle a delta bundle's carried files come from (repeatable).",
    ),
]


def _stage_options(function: Callable[..., None]) -> Callable[..., None]:
    for option in reversed(_STAGE_OPTIONS):
        function = option(function)
    return function


def _print_stage(report: "StageReport") -> None:
    for target in report.targets:
        click.echo(
            f"{target.kind}: {target.copied} copied, {target.present} already present "
            f"-> {target.destination}"
        )
        for note in target.notes:
            click.echo(f"  next: {note}")


@main.command("stage")
@click.argument("bundle", type=click.Path(exists=True, file_okay=False, path_type=Path))
@_stage_options
@_reports_errors
def stage_command(
    bundle: Path,
    policy: Path,
    state: Path,
    target_values: tuple[str, ...],
    key: Path | None,
    key_passphrase_env: str | None,
    volume_dirs: tuple[Path, ...],
    bases: tuple[Path, ...],
) -> None:
    """Copy an accepted bundle's content into local repositories, re-hashing each file."""
    from airlock.session import utc_now
    from airlock.stage import stage

    report = stage(
        bundle,
        policy=load_policy(policy),
        state=state,
        targets=_targets(target_values),
        now=utc_now(),
        signer=_key(key, key_passphrase_env),
        volume_dirs=volume_dirs,
        bases=bases,
    )
    _print_stage(report)


@patch.command("stage")
@click.argument("bundle", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option(
    "--inventory", "inventory_path", required=True, type=_FILE, help="The host's inventory."
)
@click.option(
    "--allow-downgrade", "justification", help="Stage older packages anyway, with this reason."
)
@_stage_options
@_reports_errors
def patch_stage(
    bundle: Path,
    inventory_path: Path,
    justification: str | None,
    policy: Path,
    state: Path,
    target_values: tuple[str, ...],
    key: Path | None,
    key_passphrase_env: str | None,
    volume_dirs: tuple[Path, ...],
    bases: tuple[Path, ...],
) -> None:
    """Stage patches, refusing any package older than the one installed."""
    from airlock.patch.inventory import load as load_inventory
    from airlock.patch.stage import downgrade_check
    from airlock.session import utc_now
    from airlock.stage import stage

    inventory, _ = load_inventory(inventory_path)
    report = stage(
        bundle,
        policy=load_policy(policy),
        state=state,
        targets=_targets(target_values),
        now=utc_now(),
        signer=_key(key, key_passphrase_env),
        volume_dirs=volume_dirs,
        bases=bases,
        check=downgrade_check(inventory, justification),
    )
    _print_stage(report)
    if report.downgrades_allowed:
        click.echo(f"downgrades staged: {report.downgrades_allowed}")
