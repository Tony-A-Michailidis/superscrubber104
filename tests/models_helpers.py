"""Helpers for model tests: inspect a tree in place and look at what was found."""

import textwrap
from pathlib import Path

from superscrubber104.core.model import Artifact, Finding, Result, Unit, UnitKind
from superscrubber104.core.policy import Policy, load_policy
from superscrubber104.model_inspect import InspectResult, inspect_paths
from tests.helpers import NOW

LICENCES = """\
licences:
  allow: [Apache-2.0, MIT]
  requireApproval: [LicenseRef-*]
  deny: [AGPL-*]
"""


def make_policy(directory: Path, extra: str = "", *, licences: bool = True) -> Policy:
    text = (
        "apiVersion: superscrubber104/v1alpha1\nkind: Policy\nmetadata: {name: models, version: '1'}\n"
        + (LICENCES if licences else "")
        + textwrap.dedent(extra)
    )
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return load_policy(path)


def inspect(
    root: Path,
    *,
    policy_yaml: str = "",
    licences: bool = False,
    plugins: bool = False,
    corpora: tuple[str, ...] = (),
) -> InspectResult:
    """Inspect ``root`` with a policy built from ``policy_yaml`` (kept outside ``root``).

    Scanner plugins are off unless asked for: with none configured they only add "not assessed"
    records, which tests of handlers do not care about.
    """
    policy = make_policy(root.parent / f"policy-{root.name}", policy_yaml, licences=licences)
    return inspect_paths([root], policy=policy, now=NOW, run_plugins=plugins, corpora=corpora)


def findings_of(result: InspectResult) -> dict[str, list[Finding]]:
    """Findings that are not passes, by rule."""
    grouped: dict[str, list[Finding]] = {}
    for finding in result.assessment.findings:
        if finding.result is not Result.PASS:
            grouped.setdefault(finding.rule, []).append(finding)
    return grouped


def artifact(result: InspectResult, display: str) -> Artifact:
    return next(a for a in result.analysis.artifacts if a.ref.display == display)


def package(result: InspectResult, root: str = ".") -> Unit:
    return next(
        u
        for u in result.analysis.units
        if u.kind is UnitKind.MODEL_PACKAGE and u.root.display == root
    )
