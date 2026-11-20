"""Runtime profiles, the detected inference stack and compatibility."""

from pathlib import Path

import pytest

from superscrubber104.core.model import Result, Severity, UnitKind
from superscrubber104.versions import matches_declared, numeric, satisfies
from tests.data_fixtures import embedding_model
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import docker_archive, wheel_bytes, wheel_name, write

NVIDIA_ENV = ["CUDA_VERSION=12.4.1", "NV_CUDNN_VERSION=9.1.0.70", "PATH=/usr/bin"]


@pytest.mark.parametrize(
    ("version", "constraint", "expected"),
    [
        ("550.54.15", ">=550.54.14", True),
        ("535.104.05", ">=550.54.14", False),
        ("12.4.1", ">=12.4,<12.5", True),
        ("12.5", ">=12.4,<12.5", False),
        ("2.4.0+cu121", "2.4.*", True),
        ("2.4.0+cu121", "==2.4", True),
        ("0.6.3", "0.6.*", True),
    ],
)
def test_constraints(version: str, constraint: str, expected: bool) -> None:
    assert satisfies(version, constraint) is expected


def test_declared_versions() -> None:
    assert numeric("v2.4.0+cu121") == (2, 4, 0)
    assert matches_declared("12.4.1", "12.4")
    assert not matches_declared("12.1", "12.4")
    assert matches_declared("2.4.0+cu121", "2.4.0")


def _files(**extra: bytes | str) -> dict[str, bytes | str]:
    return {
        **embedding_model("models/embedder"),
        f"wheels/{wheel_name('torch', '2.4.0+cu121')}": wheel_bytes("torch", "2.4.0+cu121"),
        f"wheels/{wheel_name('nvidia_cudnn_cu12', '9.1.0.70')}": wheel_bytes(
            "nvidia_cudnn_cu12", "9.1.0.70"
        ),
        "images/vllm.tar": docker_archive(tag="vllm/vllm-openai:v0.6.3", env=NVIDIA_ENV),
        **extra,
    }


def test_detected_stack_and_an_old_driver(tmp_path: Path) -> None:
    files = _files(**{"drivers/NVIDIA-Linux-x86_64-470.82.01.run": b"#!/bin/sh\n# makeself\n"})
    result = inspect(write(tmp_path / "d", files))
    found = findings_of(result)
    assert artifact(result, "drivers/NVIDIA-Linux-x86_64-470.82.01.run").metadata["runtime"] == {
        "component": "nvidia-driver",
        "version": "470.82.01",
    }
    [undeclared] = found["runtime.profile.undeclared"]
    detected = undeclared.detail["detected"]
    assert detected["cuda"] == ["12.1", "12.4.1"]
    assert detected["vllm"] == ["0.6.3"] and detected["nvidia-driver"] == ["470.82.01"]
    assert detected["cudnn"] == ["9.1.0.70"]
    incompatible = [f for f in found["runtime.incompatible"] if f.severity is Severity.HIGH]
    assert {f.detail["requires"]["nvidia-driver"] for f in incompatible} == {">=525.60.13"}


def test_one_environment_with_two_cuda_majors(tmp_path: Path) -> None:
    files: dict[str, bytes | str] = {
        "env/requirements.txt": "torch==2.4.0+cu118\nnvidia-cudnn-cu12==9.1.0.70\n",
        f"env/wheels/{wheel_name('torch', '2.4.0+cu118')}": wheel_bytes("torch", "2.4.0+cu118"),
        f"env/wheels/{wheel_name('nvidia_cudnn_cu12', '9.1.0.70')}": wheel_bytes(
            "nvidia_cudnn_cu12", "9.1.0.70"
        ),
    }
    found = findings_of(inspect(write(tmp_path / "d", files)))
    [mixed] = found["runtime.incompatible"]
    packages = mixed.detail["packages"]
    assert isinstance(packages, dict) and set(packages) == {"CUDA 11", "CUDA 12"}


PROFILE = """\
apiVersion: superscrubber104/v1alpha1
kind: RuntimeProfile
metadata: {name: chat-gpu}
spec:
  models: [models/embedder, models/missing]
  server: {name: vllm, version: 0.6.3}
  accelerator: {vendor: nvidia, driver: "535.104.05", cuda: "12.4", computeCapability: "8.0"}
  frameworks:
    - {name: torch, version: 2.4.0}
    - {name: transformers, version: "4.44"}
  highSide:
    - {name: nvidia-driver, version: 535.104.05}
  settings: {contextLength: 8192, temperature: 0}
"""

COMPATIBILITY = """\
runtime:
  compatibility:
    - when: {vllm: "0.6.*"}
      requires: {torch: "2.5.*"}
      reason: this site's build of vLLM 0.6 needs torch 2.5
"""


def test_declared_profile(tmp_path: Path) -> None:
    result = inspect(
        write(tmp_path / "d", _files(**{"runtime/chat.runtime.yaml": PROFILE})),
        policy_yaml=COMPATIBILITY,
    )
    [profile] = [u for u in result.analysis.units if u.kind is UnitKind.RUNTIME_PROFILE]
    assert profile.name == "chat-gpu"
    satisfied = {r.name: r.satisfied_by for r in profile.requires}
    assert satisfied["models/embedder"] == "model-package:models/embedder"
    assert satisfied["models/missing"] is None
    assert satisfied["nvidia-driver"] == "high-side:nvidia-driver"
    assert satisfied["vllm"] == "delivery" and satisfied["transformers"] is None
    found = findings_of(result)
    assert found["runtime.model.missing"][0].detail["model"] == "models/missing"
    assert [f.detail["component"] for f in found["runtime.component.missing"]] == ["transformers"]
    reasons = {(f.detail["reason"], f.severity) for f in found["runtime.incompatible"]}
    assert ("this site's build of vLLM 0.6 needs torch 2.5", Severity.HIGH) in reasons
    low = [r for r, s in reasons if s is Severity.LOW]  # 12.4 on 535: minor-version compatibility
    assert low and all("12.4" in r for r in low)
    assert "runtime.profile.undeclared" not in found
    assert profile.attributes["detected"]["cuda"] == ["12.1", "12.4.1"]


def test_cuda_installer_and_triton_python_backend(tmp_path: Path) -> None:
    triton = (
        'name: "rerank"\nbackend: "python"\nmax_batch_size: 8\ninstance_group [{kind: KIND_GPU}]\n'
    )
    result = inspect(
        write(
            tmp_path / "d",
            {
                "gpu/cuda_12.4.1_550.54.15_linux.run": b"#!/bin/sh\n",
                "repo/rerank/config.pbtxt": triton,
            },
        )
    )
    cuda = artifact(result, "gpu/cuda_12.4.1_550.54.15_linux.run").metadata["runtime"]
    assert cuda == {"component": "cuda", "version": "12.4.1", "driver": "550.54.15"}
    [python] = findings_of(result)["runtime.triton.python-backend"]
    assert python.result is Result.FAIL and python.detail["model"] == "rerank"


def test_declared_version_that_the_delivery_does_not_hold(tmp_path: Path) -> None:
    profile = PROFILE.replace("{name: torch, version: 2.4.0}", "{name: torch, version: 2.5.1}")
    result = inspect(write(tmp_path / "d", _files(**{"runtime/chat.runtime.yaml": profile})))
    [mismatch] = findings_of(result)["runtime.component.mismatch"]
    assert mismatch.detail["component"] == "torch"
    assert (mismatch.detail["declared"], mismatch.detail["delivered"]) == ("2.5.1", ["2.4.0+cu121"])
