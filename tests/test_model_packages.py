"""Model packages: grouping, completeness, consistency, licence, provenance and allowlists."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from airlock.cli import main
from airlock.core.model import Disposition, Result, Severity, TrustLevel, UnitKind, Verdict
from airlock.core.policy import Policy
from airlock.pack import pack
from airlock.verify import verify
from tests.helpers import NOW, make_site
from tests.model_fixtures import (
    APACHE,
    COMMIT,
    LLAMA,
    adapter_package,
    hf_package,
    ollama_store,
    onnx_bytes,
    safetensors_bytes,
    tiny_gguf,
    write,
)
from tests.models_helpers import artifact, findings_of, inspect, make_policy, package

# --- a complete package -------------------------------------------------------------------------


def test_complete_package_record(tmp_path: Path) -> None:
    result = inspect(hf_package(tmp_path / "tiny"), licences=True)
    found = findings_of(result)
    assert found == {}, {rule: [f.detail for f in fs] for rule, fs in found.items()}
    unit = package(result)
    a = unit.attributes
    assert unit.name == "example-org/tiny-chat"
    assert a["identity"]["architecture"] == "LlamaForCausalLM"
    assert a["identity"]["parameters"] == 32 * 8 * 2 + 8 * 8 * 2 + 8
    assert a["identity"]["publisher"] == "example-org"
    assert a["weights"]["sharded"] is True
    assert a["weights"]["formats"] == ["safetensors"]
    assert a["weights"]["index"] == ["model.safetensors.index.json"]
    assert a["tokenizer"]["tokens"] == 32
    assert a["licence"]["expression"] == "Apache-2.0"
    assert a["chatTemplates"][0]["source"] == "tokenizer_config.json#chat_template"
    assert a["modelCard"]["pipelineTag"] == "text-generation"
    assert a["modelCard"]["intendedUse"] == "Testing airlock."
    assert a["remoteCode"]["required"] is False
    provenance = a["provenance"]
    assert provenance["method"] == "huggingface-download-record"
    assert provenance["verifiedFiles"] == 3  # two shards and config.json
    assert provenance["upstream"]["revision"] == COMMIT
    roles = {m.role for m in unit.members}
    assert {"weights-shard", "weights-index", "config", "tokenizer", "tokenizer-config",
            "generation-config", "model-card", "licence", "hf-download-metadata"} <= roles  # fmt: skip

    [component] = result.analysis.components
    assert component.purl == f"pkg:huggingface/example-org/tiny-chat@{COMMIT}"
    assert component.licenses[0].expression == "Apache-2.0"
    assert component.properties["airlock:unit-digest"] == unit.digest
    shard = artifact(result, "model-00001-of-00002.safetensors")
    assert shard.verifications[0].type == "huggingface-download-record"
    assert shard.verifications[0].level is TrustLevel.CHECKSUM


def test_a_readme_and_licence_alone_are_not_a_package(tmp_path: Path) -> None:
    write(
        tmp_path, {"app/README.md": "# App\n", "app/LICENSE": APACHE, "app/main.py": "print(1)\n"}
    )
    assert inspect(tmp_path).analysis.units == ()


# --- completeness -------------------------------------------------------------------------------


def test_missing_shard(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    (root / "model-00002-of-00002.safetensors").unlink()
    [finding] = findings_of(inspect(root, licences=True))["model.package.file-missing"]
    assert finding.detail["file"] == "model-00002-of-00002.safetensors"
    assert finding.subject.display == "model-package:."


def test_index_must_match_shards(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    index = json.loads((root / "model.safetensors.index.json").read_text())
    index["weight_map"]["model.layers.0.self_attn.q_proj.weight"] = (
        "model-00002-of-00002.safetensors"
    )
    index["metadata"]["total_size"] += 2
    (root / "model.safetensors.index.json").write_text(json.dumps(index))
    write(root, {"model-old.safetensors": safetensors_bytes({"x": ("F32", [1])})})
    found = findings_of(inspect(root, licences=True))
    [mismatch] = found["model.package.index-mismatch"]
    problems = mismatch.detail["problems"]
    assert isinstance(problems, list)
    assert {p["file"] for p in problems if "file" in p} == {
        "model-00001-of-00002.safetensors",
        "model-00002-of-00002.safetensors",
    }
    assert any("indexTotalSize" in p for p in problems)
    assert found["model.package.file-unreferenced"][0].detail["file"] == "model-old.safetensors"


def test_config_must_match_weights(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    config = json.loads((root / "config.json").read_text())
    config.update(vocab_size=64, hidden_size=16, num_hidden_layers=4)
    (root / "config.json").write_text(json.dumps(config))
    (root / ".cache/huggingface/download/config.json.metadata").unlink()
    [finding] = findings_of(inspect(root, licences=True))["model.package.config-mismatch"]
    assert {p["check"] for p in finding.detail["problems"]} == {
        "vocabulary",
        "hidden size",
        "layers",
    }


def test_tokenizer_checks(tmp_path: Path) -> None:
    big = hf_package(tmp_path / "big", tokenizer_tokens=40)
    [finding] = findings_of(inspect(big, licences=True))["model.package.tokenizer-mismatch"]
    assert finding.detail == {"configVocabSize": 32, "tokenizerTokens": 40}

    none = hf_package(tmp_path / "none")
    (none / "tokenizer.json").unlink()
    assert "model.package.tokenizer-missing" in findings_of(inspect(none, licences=True))


def test_config_and_card_missing(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny", card_licence=None, download_records=False)
    (root / "config.json").unlink()
    found = findings_of(inspect(root, licences=True))
    assert "model.package.config-missing" in found
    assert "model.package.card-missing" not in found  # no config: not a transformers package

    with_config = hf_package(tmp_path / "card", card_licence=None, download_records=False)
    assert "model.package.card-missing" in findings_of(inspect(with_config, licences=True))


# --- provenance ---------------------------------------------------------------------------------


def test_publisher_checksum_mismatch_is_final(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    shard = root / "model-00002-of-00002.safetensors"
    data = bytearray(shard.read_bytes())
    data[-1] = 1  # same size, still valid safetensors, different content
    shard.write_bytes(bytes(data))
    result = inspect(root, licences=True)
    [finding] = findings_of(result)["model.provenance.checksum-mismatch"]
    assert finding.subject.display == "model-00002-of-00002.safetensors"
    assert finding.detail["method"] == "sha256"
    decision = next(d for d in result.assessment.decisions if d.finding == finding.id)
    assert decision.final
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_small_files_are_checked_against_their_git_blob_hash(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    config = json.loads((root / "config.json").read_text())
    config["torch_dtype"] = "bfloat16"
    (root / "config.json").write_text(json.dumps(config))
    [finding] = findings_of(inspect(root, licences=True))["model.provenance.checksum-mismatch"]
    assert finding.subject.display == "config.json"
    assert finding.detail["method"] == "git-blob-sha1"


# --- remote code --------------------------------------------------------------------------------


def test_remote_code(tmp_path: Path) -> None:
    local = hf_package(
        tmp_path / "local", auto_map={"AutoModelForCausalLM": "modeling_tiny.TinyForCausalLM"}
    )
    write(local, {"modeling_tiny.py": "import torch\n"})
    found = findings_of(inspect(local, licences=True))
    [required] = found["model.remote-code.required"]
    assert required.detail["files"] == ["modeling_tiny.py"]
    assert "model.remote-code.external" not in found
    assert "model.package.file-missing" not in found

    missing = hf_package(
        tmp_path / "missing", auto_map={"AutoConfig": "configuration_tiny.TinyConfig"}
    )
    found = findings_of(inspect(missing, licences=True))
    assert found["model.package.file-missing"][0].detail["file"] == "configuration_tiny.py"

    external = hf_package(
        tmp_path / "external", auto_map={"AutoModel": "other-org/code--modeling_x.X"}
    )
    found = findings_of(inspect(external, licences=True))
    assert found["model.remote-code.external"][0].detail["references"] == [
        "other-org/code--modeling_x.X"
    ]
    decision = next(d for d in inspect(external, licences=True).assessment.decisions
                    if d.finding == found["model.remote-code.required"][0].id)  # fmt: skip
    assert decision.disposition is Disposition.BLOCK
    assert not decision.final  # a policy blocker: overridable by a quorum


# --- adapters and requirements ------------------------------------------------------------------


def test_adapter_base_model_in_the_delivery(tmp_path: Path) -> None:
    hf_package(tmp_path / "d" / "base")
    adapter_package(tmp_path / "d" / "lora")
    result = inspect(tmp_path / "d", licences=True)
    unit = package(result, "lora")
    [need] = unit.requires
    assert need.relation == "base-model"
    assert need.satisfied_by == "model-package:base"
    assert unit.attributes["adapter"]["rank"] == 8
    assert "model.package.requirement-unmet" not in findings_of(result)


def test_adapter_without_its_base(tmp_path: Path) -> None:
    result = inspect(adapter_package(tmp_path / "lora"), licences=True)
    [finding] = findings_of(result)["model.package.requirement-unmet"]
    assert finding.detail["name"] == "example-org/tiny-chat"
    assert package(result).requires[0].satisfied_by is None


# --- licences -----------------------------------------------------------------------------------


def test_custom_model_licence_needs_approval(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny", licence=LLAMA, card_licence="llama3.1")
    result = inspect(root, licences=True)
    [finding] = findings_of(result)["licence.approval-required"]
    assert finding.detail["expression"] == "LicenseRef-llama3.1"
    assert finding.attributes == {"licence": "LicenseRef-llama3.1"}


def test_licence_conflict_denied_and_missing(tmp_path: Path) -> None:
    conflict = hf_package(tmp_path / "conflict", licence=APACHE, card_licence="agpl-3.0")
    found = findings_of(inspect(conflict, licences=True))
    assert "licence.conflict" in found
    assert found["licence.denied"][0].detail["expression"] == "AGPL-3.0-only AND Apache-2.0"

    none = hf_package(tmp_path / "none", licence=None, card_licence=None)
    assert "licence.missing" in findings_of(inspect(none, licences=True))

    other = hf_package(
        tmp_path / "other", licence=None, card_licence="other\nlicense_name: Acme Model Terms"
    )
    unit = package(inspect(other, licences=True))
    assert unit.attributes["licence"]["expression"] == "LicenseRef-acme-model-terms"

    unknown = hf_package(tmp_path / "unknown", licence="Some home-grown terms.", card_licence=None)
    assert "licence.unidentified" in findings_of(inspect(unknown, licences=True))


def test_gated_model_is_recorded(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny", card_licence="apache-2.0\nextra_gated_prompt: Agree first")
    assert package(inspect(root, licences=True)).attributes["licence"]["gated"] is True


def test_model_card_aliases_are_refused(tmp_path: Path) -> None:
    bomb = "---\na: &a ['x','x','x','x','x','x','x','x','x']\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a]\nlicense: [*b,*b,*b,*b]\n---\n"
    root = hf_package(tmp_path / "tiny", card_licence=None)
    write(root, {"README.md": bomb})
    unit = package(inspect(root, licences=True))
    assert "modelCard" not in unit.attributes  # front matter rejected, nothing expanded


# --- allowlist and the second layer of trust ----------------------------------------------------


def test_model_allowlist(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    digest = package(inspect(root, licences=True)).digest

    enforce = f"allowlists:\n  models: {{mode: enforce, entries: [{{digest: '{digest}'}}]}}\n"
    result = inspect(root, policy_yaml=enforce, licences=True)
    assert "model.allowlist.unapproved" not in findings_of(result)
    assert package(result).attributes["allowlist"]["matchedBy"] == "digest"
    pinned = artifact(result, "model-00001-of-00002.safetensors").verifications
    assert TrustLevel.PINNED_CHECKSUM in {v.level for v in pinned}

    by_id = (
        "allowlists:\n  models: {mode: enforce, entries: "
        f"[{{id: 'huggingface:example-org/tiny-chat', revision: '{COMMIT}'}}]}}\n"
    )
    assert "model.allowlist.unapproved" not in findings_of(
        inspect(root, policy_yaml=by_id, licences=True)
    )

    other = "allowlists:\n  models: {mode: enforce, entries: [{id: 'huggingface:someone/else'}]}\n"
    [finding] = findings_of(inspect(root, policy_yaml=other, licences=True))[
        "model.allowlist.unapproved"
    ]
    assert finding.severity is Severity.HIGH
    report = other.replace("enforce", "report")
    [finding] = findings_of(inspect(root, policy_yaml=report, licences=True))[
        "model.allowlist.unapproved"
    ]
    assert finding.severity is Severity.INFO


def test_minimum_upstream_trust(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    minimum = "trust:\n  minimum: {'model.safetensors': pinned-checksum}\n"
    found = findings_of(inspect(root, policy_yaml=minimum, licences=True))
    insufficient = {f.subject.display: f for f in found["trust.upstream.insufficient"]}
    assert set(insufficient) == {
        "model-00001-of-00002.safetensors",
        "model-00002-of-00002.safetensors",
    }
    assert insufficient["model-00001-of-00002.safetensors"].detail["established"] == "checksum"

    digest = package(inspect(root, licences=True)).digest
    pinned = (
        minimum + f"allowlists:\n  models: {{mode: enforce, entries: [{{digest: '{digest}'}}]}}\n"
    )
    assert "trust.upstream.insufficient" not in findings_of(
        inspect(root, policy_yaml=pinned, licences=True)
    )


# --- GGUF, Ollama, Modelfile, sentence-transformers ---------------------------------------------


def test_gguf_files_share_the_directory_licence(tmp_path: Path) -> None:
    write(
        tmp_path / "g",
        {"tiny-Q4.gguf": tiny_gguf(), "tiny-F16.gguf": tiny_gguf(), "LICENSE": LLAMA},
    )
    result = inspect(tmp_path / "g", licences=True)
    units = {u.root.display: u for u in result.analysis.units}
    assert set(units) == {"tiny-F16.gguf", "tiny-Q4.gguf"}
    for unit in units.values():
        declared = unit.attributes["licence"]["declared"]
        assert {d["source"] for d in declared} == {"licence-file:LICENSE", "gguf-metadata"}
        assert unit.attributes["identity"]["architecture"] == "llama"


def test_onnx_variants_belong_to_their_repository(tmp_path: Path) -> None:
    # Hugging Face repositories keep format variants in onnx/ and openvino/ subfolders.
    root = hf_package(tmp_path / "models" / "tiny")
    write(root, {"onnx/model.onnx": onnx_bytes(), "onnx/model_int8.onnx": onnx_bytes()})
    write(tmp_path / "models" / "loose", {"onnx/model.onnx": onnx_bytes()})
    result = inspect(tmp_path / "models", licences=True)
    units = {u.root.display: u for u in result.analysis.units}
    variant = units["tiny/onnx/model_int8.onnx"]
    assert variant.attributes["variantOf"] == "tiny"
    assert variant.name == "tiny/onnx/model_int8.onnx"
    assert variant.attributes["licence"]["expression"] == "Apache-2.0"
    missing = {f.subject.unit for f in findings_of(result).get("licence.missing", [])}
    assert missing == {"model-package:loose/onnx/model.onnx"}  # no repository around it
    # Inspecting the repository itself: the variant is named from there, without "./".
    alone = {u.root.display: u for u in inspect(root).analysis.units}
    assert alone["onnx/model_int8.onnx"].name == "onnx/model_int8.onnx"


def test_split_gguf_completeness(tmp_path: Path) -> None:
    write(
        tmp_path / "g",
        {
            "big-00001-of-00003.gguf": tiny_gguf(**{"split.no": 0, "split.count": 3}),
            "big-00003-of-00003.gguf": tiny_gguf(**{"split.no": 2, "split.count": 3}),
        },
    )
    result = inspect(tmp_path / "g")
    [finding] = findings_of(result)["model.package.file-missing"]
    assert finding.detail["file"] == "big-00002-of-00003.gguf"
    assert package(result, "big-00001-of-00003.gguf").attributes["weights"]["sharded"] is True


def test_ollama_store(tmp_path: Path) -> None:
    result = inspect(ollama_store(tmp_path / "models"), licences=True)
    unit = package(result, "manifests/registry.ollama.ai/library/tiny/latest")
    assert unit.name == "registry.ollama.ai/library/tiny:latest"
    roles = sorted(m.role for m in unit.members)
    assert roles == [
        "chat-template",
        "licence",
        "ollama-config",
        "ollama-manifest",
        "params",
        "weights",
    ]
    assert unit.attributes["identity"]["architecture"] == "llama"
    assert unit.attributes["licence"]["expression"] == "LicenseRef-llama3.1"
    assert unit.attributes["provenance"]["upstream"]["type"] == "ollama"
    found = findings_of(result)
    assert set(found) == {"licence.approval-required"}
    weights = next(m for m in unit.members if m.role == "weights")
    assert (
        artifact(result, weights.artifact.display).verifications[0].type == "ollama-manifest-digest"
    )


def test_ollama_store_damage(tmp_path: Path) -> None:
    tampered = inspect(ollama_store(tmp_path / "t", tamper=True))
    [finding] = findings_of(tampered)["model.provenance.checksum-mismatch"]
    assert finding.detail["source"] == "ollama manifest"
    assert tampered.assessment.summary.verdict is Verdict.REFUSED

    dropped = inspect(ollama_store(tmp_path / "d", drop="application/vnd.ollama.image.license"))
    [missing] = findings_of(dropped)["model.package.file-missing"]
    assert missing.detail["role"] == "licence"


@pytest.mark.parametrize(
    ("modelfile", "rule", "detail"),
    [
        ("FROM llama3.1:8b\n", "model.package.requirement-unmet", "llama3.1:8b"),
        ("FROM ./missing.gguf\n", "model.package.file-missing", "missing.gguf"),
        (
            "FROM /home/user/models/x.gguf\n",
            "model.package.path-escape",
            "/home/user/models/x.gguf",
        ),
    ],
)
def test_modelfile_references(tmp_path: Path, modelfile: str, rule: str, detail: str) -> None:
    write(tmp_path / "m", {"Modelfile": modelfile + 'TEMPLATE """{{ .Prompt }}"""\n'})
    [finding] = findings_of(inspect(tmp_path / "m"))[rule]
    assert detail in json.dumps(finding.detail)


def test_modelfile_with_local_weights(tmp_path: Path) -> None:
    write(
        tmp_path / "m",
        {"Modelfile": "FROM ./tiny.gguf\nPARAMETER temperature 0.2\n", "tiny.gguf": tiny_gguf()},
    )
    result = inspect(tmp_path / "m")
    found = findings_of(result)
    assert "model.package.file-missing" not in found
    assert "model.package.requirement-unmet" not in found
    modelfile_unit = package(result)
    assert any(m.role == "modelfile" for m in modelfile_unit.members)


def test_sentence_transformers(tmp_path: Path) -> None:
    write(
        tmp_path / "e",
        {
            "config.json": json.dumps(
                {
                    "architectures": ["BertModel"],
                    "model_type": "bert",
                    "hidden_size": 8,
                    "vocab_size": 16,
                }
            ),
            "model.safetensors": safetensors_bytes(
                {"embeddings.word_embeddings.weight": ("F32", [16, 8])}
            ),
            "vocab.txt": "\n".join(f"w{i}" for i in range(16)) + "\n",
            "modules.json": json.dumps(
                [
                    {
                        "idx": 0,
                        "name": "0",
                        "path": "",
                        "type": "sentence_transformers.models.Transformer",
                    },
                    {
                        "idx": 1,
                        "name": "1",
                        "path": "1_Pooling",
                        "type": "sentence_transformers.models.Pooling",
                    },
                    {
                        "idx": 2,
                        "name": "2",
                        "path": "2_Normalize",
                        "type": "sentence_transformers.models.Normalize",
                    },
                ]
            ),
            "1_Pooling/config.json": json.dumps(
                {"word_embedding_dimension": 8, "pooling_mode_mean_tokens": True}
            ),
        },
    )
    unit = package(inspect(tmp_path / "e"))
    assert unit.attributes["embedding"] == {
        "dimension": 8,
        "pooling": "mean_tokens",
        "normalize": True,
    }
    assert unit.attributes["tokenizer"]["tokens"] == 16


# --- archives, pack and verify, CLI -------------------------------------------------------------


def test_package_inside_an_archive(tmp_path: Path) -> None:
    source = hf_package(tmp_path / "src", download_records=False)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, f"tiny/{path.relative_to(source).as_posix()}")
    write(tmp_path / "d", {"bundle.zip": buffer.getvalue()})
    result = inspect(tmp_path / "d", licences=True)
    unit = package(result, "bundle.zip!/tiny")
    assert unit.attributes["weights"]["sharded"] is True
    assert "model.package.file-missing" not in findings_of(result)


def test_pack_and_verify_rederive_model_packages(tmp_path: Path) -> None:
    site = make_site(tmp_path / "site")
    delivery = tmp_path / "delivery"
    hf_package(delivery / "models" / "tiny")
    write(
        delivery,
        {"app/main.py": "print('hi')\n", "docs/README.md": "# Docs\n", "vendor/x.txt": "x"},
    )
    request = site.request.read_text().replace(
        '{name: model, paths: ["models/**"]}',
        '{name: model, unit: model-package, paths: ["models/**"]}',
    )
    site.request.write_text(request)
    policy = make_policy(tmp_path / "packer", licences=True)
    packed = pack(
        [delivery],
        tmp_path / "bundle",
        signer=site.pack_key,
        policy=policy,
        request_path=site.request,
        now=NOW,
    )
    assert packed.signed
    assert "request.content.unit-missing" not in {
        f.rule for f in packed.assessment.findings if f.result is Result.FAIL
    }
    analysis = json.loads((packed.bundle / "analysis.json").read_bytes())
    assert [u["root"]["path"] for u in analysis["units"]] == ["models/tiny"]

    receiving = site.policy("licences: {allow: [Apache-2.0]}\n")
    result = verify(packed.bundle, policy=receiving, now=NOW)
    assert result.assessment.summary.verdict is Verdict.PASSED, [
        (f.rule, f.subject.display) for f in result.assessment.findings if f.result is Result.FAIL
    ]

    (tmp_path / "bundle/payload/models/tiny/config.json").unlink()
    broken = verify(packed.bundle, policy=receiving, now=NOW)
    assert "integrity.entry.missing" in {
        f.rule for f in broken.assessment.findings if f.result is Result.FAIL
    }


def test_declared_unit_that_does_not_form(tmp_path: Path) -> None:
    site = make_site(tmp_path / "site")
    delivery = write(
        tmp_path / "delivery",
        {
            "models/tiny/README.md": "# not a model\n",
            "app/a.py": "",
            "docs/d.md": "",
            "vendor/v": "",
        },
    )
    site.request.write_text(
        site.request.read_text().replace(
            '{name: model, paths: ["models/**"]}',
            '{name: model, unit: model-package, paths: ["models/**"]}',
        )
    )
    packed = pack(
        [delivery],
        tmp_path / "bundle",
        signer=site.pack_key,
        policy=Policy.default(),
        request_path=site.request,
        now=NOW,
    )
    [finding] = [f for f in packed.assessment.findings if f.rule == "request.content.unit-missing"]
    assert finding.detail["content"] == "model"


def test_model_inspect_command(tmp_path: Path) -> None:
    root = hf_package(tmp_path / "tiny")
    result = CliRunner().invoke(main, ["model", "inspect", str(root)])
    assert "model package  .  (example-org/tiny-chat)" in result.output
    assert "LlamaForCausalLM" in result.output
    assert f"example-org/tiny-chat@{COMMIT}, 3 file(s) verified" in result.output
    assert result.output.isascii()

    as_json = CliRunner().invoke(main, ["model", "inspect", "--json", str(root)])
    document = json.loads(as_json.output)
    assert document["units"][0]["kind"] == UnitKind.MODEL_PACKAGE.value
    assert document["components"][0]["type"] == "machine-learning-model"

    evil = write(tmp_path / "evil", {"model.pkl": b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00idR."})
    refused = CliRunner().invoke(main, ["model", "inspect", str(evil)])
    assert refused.exit_code == 1
    assert "model.pickle.dangerous-import" in refused.output
    assert hashlib.sha256(b"").hexdigest()  # keep hashlib referenced for readability of fixtures
