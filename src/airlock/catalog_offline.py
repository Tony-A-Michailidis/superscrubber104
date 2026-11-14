"""Built-in rules for offline readiness and runtime profiles.

Offline findings carry an ``impact`` attribute: ``will-break`` (the delivery fails on a network
with no internet), ``egress-risk`` (it would send data out if it found a route) or
``informational``. Policy decides which of them block, for example
``{rule: "offline.*", where: {impact: egress-risk}, disposition: block}``.

None of these is final: they describe what content does, which is a policy matter.
"""

from airlock.core.model import Severity
from airlock.core.rules import RuleSpec

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO  # noqa: E741


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    controls: tuple[str, ...],
    rationale: str,
    *,
    remediation: str = "",
) -> RuleSpec:
    return RuleSpec(rule_id, "1", title, severity, controls, rationale, remediation, False)


OFFLINE = (
    _rule(
        "offline.download.runtime",
        "Code or configuration downloads something when it runs or builds",
        M,
        ("SC-7", "CM-7", "CM-11"),
        "Model hubs, package installs, torch.hub, NLTK, spaCy, tiktoken encodings, ollama pull: "
        "on a network with no internet these fail, or worse, find a route out.",
        remediation="Deliver what is downloaded and point the code at the local copy.",
    ),
    _rule(
        "offline.config.missing",
        "Libraries that download on demand are used without their offline setting",
        L,
        ("CM-6", "SC-7"),
        "Without HF_HUB_OFFLINE and similar settings, a library that finds no local copy tries "
        "the internet and waits for a timeout before failing.",
        remediation="Set the recommended offline configuration on the high side.",
    ),
    _rule(
        "offline.telemetry.enabled",
        "A library or tool sends usage data by default",
        M,
        ("SC-7", "AC-4", "CM-7"),
        "Gradio, Streamlit, Chroma, vLLM, Weights & Biases, LangSmith tracing and analytics SDKs "
        "report to their vendors unless switched off. Behind the gap that is an attempted "
        "egress, every time.",
        remediation="Switch it off in the configuration the finding names.",
    ),
    _rule(
        "offline.update.enabled",
        "Automatic updates or update checks are enabled",
        M,
        ("CM-3", "CM-11", "SC-7"),
        "A tool that updates itself changes what was approved, and checks for updates over the "
        "network.",
    ),
    _rule(
        "offline.endpoint.cloud-ai",
        "Code calls a cloud AI service",
        H,
        ("SC-7", "AC-4"),
        "Prompts and documents sent to a hosted model leave the enclave. A client created "
        "without a local base URL talks to its vendor by default.",
        remediation="Point the client at the local inference server, or remove it.",
    ),
    _rule(
        "offline.endpoint.external",
        "Code or configuration names external hosts",
        L,
        ("SC-7",),
        "Hard-coded public hosts are where the delivery will try to connect.",
    ),
    _rule(
        "offline.registry.external",
        "A manifest refers to a container image that is not in the delivery",
        M,
        ("CM-8", "SC-7"),
        "Compose files, Kubernetes manifests and Dockerfiles pull images; without them in the "
        "delivery they fail on the high side.",
    ),
    _rule(
        "offline.network.public-service",
        "Configuration uses public DNS or time servers",
        L,
        ("SC-7", "CM-6"),
        "Public resolvers and NTP pools are not reachable behind the gap; the high side has "
        "its own.",
    ),
)

RUNTIME = (
    _rule(
        "runtime.component.missing",
        "A component of the runtime profile is neither delivered nor installed on the high side",
        H,
        ("CM-8", "SA-22"),
        "The profile names the stack the models were tested on; the high side must have every "
        "part of it.",
    ),
    _rule(
        "runtime.component.mismatch",
        "A delivered component differs from the version the runtime profile declares",
        M,
        ("CM-8", "CM-2"),
        "The stack that crosses is not the stack the models were tested on.",
    ),
    _rule(
        "runtime.incompatible",
        "Runtime components are known to be incompatible",
        H,
        ("CM-6", "SA-22"),
        "A CUDA build that needs a newer driver than the profile declares, a framework built "
        "for one CUDA major version beside libraries for another: it will not run.",
    ),
    _rule(
        "runtime.model.missing",
        "A runtime profile names a model that is not in the delivery",
        H,
        ("CM-8",),
        "The profile pairs models with a stack; the models must cross too.",
    ),
    _rule(
        "runtime.profile.undeclared",
        "Models and an inference stack cross without a runtime profile",
        I,
        ("CM-8", "CM-2"),
        "Without a declared profile the high side cannot check that it reproduces the stack "
        "the models were tested on. The detected stack is recorded for reference.",
    ),
    _rule(
        "runtime.triton.python-backend",
        "Triton model uses the Python backend",
        M,
        ("CM-7", "SI-3"),
        "A Python-backend model runs its model.py inside the server: it is code, not data.",
    ),
)

OFFLINE_RULES = (*OFFLINE, *RUNTIME)
