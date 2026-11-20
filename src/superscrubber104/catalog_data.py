"""Built-in rules for the data side of an AI system: notebooks, datasets, knowledge bases (RAG
indexes and their corpora), classic ML models and MLflow models.

Only the publisher-signature failures are final: a signature that does not hold, or a file that
differs from what its publisher signed, is an authenticity failure like a bundle hash mismatch.
Everything else describes what content does or lacks, which is a policy matter.
"""

from superscrubber104.core.model import Severity
from superscrubber104.core.rules import RuleSpec

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO  # noqa: E741


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    controls: tuple[str, ...],
    rationale: str,
    *,
    remediation: str = "",
    final: bool = False,
) -> RuleSpec:
    return RuleSpec(rule_id, "1", title, severity, controls, rationale, remediation, final)


NOTEBOOKS = (
    _rule(
        "notebook.output.saved",
        "Notebook was saved with cell outputs",
        L,
        ("AC-4",),
        "Outputs carry whatever the notebook printed: data samples, file paths, host names, "
        "tokens. They cross with the notebook and nobody reviews them as code.",
        remediation="Clear outputs before delivery (jupyter nbconvert --clear-output).",
    ),
    _rule(
        "notebook.cell.network",
        "Notebook installs packages or downloads content when it runs",
        M,
        ("SC-7", "CM-11"),
        "pip install, wget, git clone and similar cells need the internet; on the high side "
        "they fail, or worse, find a route out.",
        remediation="Ship the packages and files in the delivery and remove the cells.",
    ),
    _rule(
        "notebook.cell.shell",
        "Notebook runs shell commands",
        L,
        ("CM-7",),
        "Shell escapes (!cmd, %%bash) run with the user's rights wherever the notebook is opened "
        "and run.",
    ),
)

DATASETS = (
    _rule(
        "dataset.remote-code.required",
        "Dataset is loaded by a Python script that ships with it",
        H,
        ("CM-7", "SI-3"),
        "A dataset loading script runs arbitrary code (trust_remote_code), and usually "
        "downloads the data from URLs when it runs.",
        remediation="Convert the dataset to Parquet or Arrow files and drop the script.",
    ),
    _rule(
        "dataset.file-missing",
        "Dataset refers to a data file that is not in the delivery",
        H,
        ("CM-8",),
        "A split or shard named by the dataset's own metadata is missing; loading fails or "
        "silently uses less data.",
    ),
    _rule(
        "dataset.file.malformed",
        "Data file is truncated or malformed",
        M,
        ("SI-7",),
        "The file's own structure does not hold together: a truncated download or a damaged copy.",
    ),
)

KNOWLEDGE = (
    _rule(
        "kb.embedding-model.missing",
        "Knowledge base was built with an embedding model that is not in the delivery",
        H,
        ("CM-8",),
        "Queries must be embedded with the model that built the index. Without it the index "
        "cannot be searched on the high side.",
    ),
    _rule(
        "kb.embedding-model.mismatch",
        "Knowledge base dimension does not match its embedding model",
        H,
        ("CM-8", "SI-7"),
        "Vectors of a different width cannot be compared; the index is useless with this model.",
    ),
    _rule(
        "kb.embedding-model.unrecorded",
        "Knowledge base does not record which embedding model built it",
        L,
        ("CM-8",),
        "The index format does not say which model produced its vectors. The dimension and the "
        "candidate models in the delivery are recorded so a reviewer can confirm the pairing.",
    ),
    _rule(
        "kb.corpus.injection",
        "Knowledge-base content contains instructions aimed at a model",
        H,
        ("SI-3", "SI-10"),
        "Retrieved text is placed in the model's context. Instructions planted in a document "
        "reach the model as if the user had written them; no traditional scanner looks for "
        "this.",
    ),
    _rule(
        "kb.corpus.hidden-characters",
        "Knowledge-base content contains invisible characters",
        M,
        ("SI-3", "SI-10"),
        "Zero-width and bidirectional characters hide text from a human reviewer while the "
        "model still reads it.",
    ),
    _rule(
        "kb.corpus.hidden-text",
        "Knowledge-base document hides text from a reader",
        M,
        ("SI-3", "SI-10"),
        "CSS that hides an element, Word's hidden or white text, PDF text in the invisible "
        "rendering mode: a reviewer does not see it, a text extractor passes it to the model.",
    ),
    _rule(
        "kb.index.malformed",
        "Vector index or store is malformed",
        M,
        ("SI-7",),
        "The index does not hold together (bad header, truncated, unreadable database).",
    ),
)

SIGNATURES = (
    _rule(
        "model.signature.invalid",
        "Model signature does not verify",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "The publisher's signature, its transparency-log promise or its log entry does not hold: "
        "the signature or the statement it covers was altered.",
        final=True,
    ),
    _rule(
        "model.signature.digest-mismatch",
        "Model file differs from what its publisher signed",
        C,
        ("SI-7", "SR-11"),
        "The file's sha256 is not the one in the publisher's signed statement.",
        final=True,
    ),
    _rule(
        "model.signature.untrusted",
        "Model signature is not from a key, CA or identity the policy trusts",
        M,
        ("SR-4", "SR-11"),
        "The signature may well be genuine, but nothing pinned in the policy says whose it is. "
        "Pin the publisher's key, CA or Sigstore identity under trust.upstream.",
    ),
    _rule(
        "model.signature.incomplete",
        "Model package holds files its signature does not cover, or lacks files it does",
        M,
        ("SI-7", "CM-8"),
        "A file added after signing (or left out of the delivery) is not vouched for by the "
        "publisher.",
    ),
)

EVALS = (
    _rule(
        "eval.set.malformed",
        "Evaluation set or results file is malformed",
        M,
        ("SA-11",),
        "An evaluation set that cannot be read cannot verify anything.",
    ),
    _rule(
        "eval.model.missing",
        "Evaluation set names a model that is not in the delivery",
        H,
        ("SA-11", "CM-8"),
        "The set crosses to verify a model; the model must cross with it.",
    ),
    _rule(
        "eval.reference.mismatch",
        "Reference results are not for the delivered evaluation set",
        H,
        ("SA-11", "SI-7"),
        "Results from a different set (or a different version of it) prove nothing about this one.",
    ),
    _rule(
        "eval.model.digest-mismatch",
        "The evaluated model is not the delivered model",
        C,
        ("SI-7", "SR-11"),
        "The reference results were produced with a model whose files differ from the ones that "
        "crossed: a swapped model.",
        final=True,
    ),
    _rule(
        "eval.output.diverged",
        "Model output differs from the reference beyond the allowed tolerance",
        H,
        ("SA-11", "SI-7"),
        "Same set, same model files, same settings, different behaviour: the runtime differs, or "
        "the model is not behaving as it did on the low side.",
    ),
    _rule(
        "eval.case.failed",
        "Model output does not meet a case's expectation",
        M,
        ("SA-11",),
        "The model does not do what the evaluation set says it should.",
    ),
    _rule(
        "eval.canary.failed",
        "Model fails a canary prompt",
        H,
        ("SA-11", "SI-3"),
        "Canary prompts probe for known backdoor triggers and guardrail verdicts; a failure is a "
        "behaviour the model should not have.",
    ),
    _rule(
        "eval.runtime.error",
        "The runtime failed on a case",
        H,
        ("SA-11",),
        "A case that did not run was not evaluated.",
    ),
)

MODELS = (
    _rule(
        "model.mlflow.custom-code",
        "MLflow model runs custom Python code when loaded",
        H,
        ("CM-7", "SI-3"),
        "A python_function model with its own loader module or a pickled python_model runs "
        "code that ships with the model.",
    ),
    _rule(
        "model.skops.untrusted-type",
        "skops model contains types outside the trusted set",
        H,
        ("SI-3", "CM-7"),
        "skops refuses untrusted types unless the loader lists them as trusted; whatever is "
        "listed is instantiated, and some types run code.",
    ),
)

DATA_RULES = (*NOTEBOOKS, *DATASETS, *KNOWLEDGE, *MODELS, *SIGNATURES, *EVALS)
