"""Infrastructure code: Kubernetes and Compose posture, unpinned images, Helm, Terraform and Ansible
dependencies, Terraform provider hashes. Real files were also checked: kube-prometheus's
node-exporter DaemonSet, the kube-prometheus-stack chart and HashiCorp's null provider."""

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
import yaml

from airlock.core.model import Result, Verdict
from airlock.core.yamlio import load_untrusted_yaml
from airlock.formats.golang import zip_hash
from tests.models_helpers import artifact, findings_of, inspect
from tests.software_fixtures import write

DEPLOYMENT = """\
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  template:
    spec:
      hostNetwork: true
      securityContext: {runAsUser: 0}
      volumes:
        - name: sock
          hostPath: {path: /var/run/docker.sock}
        - name: logs
          hostPath: {path: /var/log}
      containers:
        - name: app
          image: registry.example.org/app:1.2
          securityContext:
            privileged: true
            capabilities: {add: [NET_ADMIN, SYS_ADMIN]}
        - name: side
          image: registry.example.org/side@sha256:%s
---
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - {name: job, image: busybox}
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec: {ports: [{port: 80}]}
""" % ("a" * 64)


def _failing(result, rule: str) -> dict[str, dict]:  # type: ignore[no-untyped-def,type-arg]
    return {
        f.subject.display: dict(f.detail)
        for f in findings_of(result).get(rule, [])
        if f.result is Result.FAIL
    }


def test_kubernetes_workload_posture(tmp_path: Path) -> None:
    result = inspect(write(tmp_path / "d", {"deploy/app.yaml": DEPLOYMENT}))
    meta = artifact(result, "deploy/app.yaml").metadata["iac"]
    assert meta["kinds"] == {"Deployment": 1, "CronJob": 1, "Service": 1}
    privileged = _failing(result, "iac.workload.privileged")["deploy/app.yaml#Deployment/web"]
    assert privileged["settings"] == [
        "app: capability SYS_ADMIN",
        "app: privileged",
        "hostPath /var/run/docker.sock",
    ]
    host = _failing(result, "iac.workload.host-access")["deploy/app.yaml#Deployment/web"]
    assert host["settings"] == ["app: capability NET_ADMIN", "hostNetwork", "hostPath /var/log"]
    assert _failing(result, "iac.workload.root")["deploy/app.yaml#Deployment/web"]["settings"] == [
        "pod runAsUser: 0"
    ]
    unpinned = _failing(result, "iac.image.unpinned")
    assert unpinned["deploy/app.yaml#Deployment/web"]["images"] == [
        {"image": "registry.example.org/app:1.2", "why": "tag, not digest"}
    ]
    assert (
        unpinned["deploy/app.yaml#CronJob/nightly"]["images"][0]["why"] == "no tag (means latest)"
    )


def test_compose_with_anchors(tmp_path: Path) -> None:
    compose = """\
x-common: &common
  restart: always
  image: registry.example.org/base:latest
services:
  agent:
    <<: *common
    privileged: true
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data
    user: root
  quiet:
    image: registry.example.org/quiet@sha256:%s
""" % ("b" * 64)
    result = inspect(write(tmp_path / "d", {"compose.yaml": compose}))
    assert _failing(result, "iac.workload.privileged")["compose.yaml#service/agent"][
        "settings"
    ] == [
        "mounts /var/run/docker.sock",
        "privileged",
    ]
    assert _failing(result, "iac.workload.host-access")["compose.yaml#service/agent"][
        "settings"
    ] == ["network_mode: host"]
    assert "compose.yaml#service/agent" in _failing(result, "iac.workload.root")
    assert list(_failing(result, "iac.image.unpinned")) == ["compose.yaml#service/agent"]


def test_alias_bombs_are_refused() -> None:
    lines = ["a: &a [x, x, x, x, x, x, x, x, x, x]"]
    for level in range(1, 8):
        previous = chr(ord("a") + level - 1)
        name = chr(ord("a") + level)
        lines.append(f"{name}: &{name} [{', '.join([f'*{previous}'] * 10)}]")
    with pytest.raises(yaml.YAMLError, match="expand"):
        load_untrusted_yaml("\n".join(lines), aliases=True)
    assert load_untrusted_yaml("a: &a {x: 1}\nb: *a\nc: =\n", aliases=True) == {
        "a": {"x": 1},
        "b": {"x": 1},
        "c": "=",
    }


def test_helm_chart_dependencies(tmp_path: Path) -> None:
    chart = """\
apiVersion: v2
name: app
version: 1.0.0
dependencies:
  - {name: redis, version: "~18.0.0", repository: "https://charts.example.org"}
  - {name: common, version: 2.x.x, repository: "https://charts.example.org"}
  - {name: local, version: 0.1.0, repository: "file://../local"}
  - {name: gone, version: 1.0.0, repository: "oci://registry.example.org/charts"}
"""
    lock = "dependencies:\n  - {name: redis, version: 18.0.4}\n"
    files: dict[str, bytes | str] = {
        "charts/app/Chart.yaml": chart,
        "charts/app/Chart.lock": lock,
        "charts/app/charts/redis-18.0.4.tgz": b"\x1f\x8b",
        "charts/app/charts/common/Chart.yaml": "apiVersion: v2\nname: common\nversion: 2.1.0\n",
        "charts/app/templates/deploy.yaml": "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n"
        "  name: {{ .Release.Name }}\n",
        "charts/local/Chart.yaml": "apiVersion: v2\nname: local\nversion: 0.1.0\n",
    }
    result = inspect(write(tmp_path / "d", files))
    [missing] = _failing(result, "iac.dependency.unresolvable").values()
    assert missing["missing"] == [
        {"chart": "gone", "version": "1.0.0", "repository": "oci://registry.example.org/charts"}
    ]
    assert artifact(result, "charts/app/templates/deploy.yaml").kind == "helm.template"
    not_assessed = [
        f.subject.display
        for f in result.assessment.findings
        if f.rule == "iac.workload.privileged" and f.result is Result.NOT_ASSESSED
    ]
    assert "charts/app/Chart.yaml#templates" in not_assessed


def _provider_zip() -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        archive.writestr("terraform-provider-thing_v1.0.0_x5", b"\x7fELF provider")
    return out.getvalue()


def test_terraform_providers_and_modules(tmp_path: Path) -> None:
    good = _provider_zip()
    h1 = zip_hash(io.BytesIO(good))
    lock = f"""\
provider "registry.terraform.io/example/thing" {{
  version = "1.0.0"
  hashes = [
    "{h1}",
    "zh:{hashlib.sha256(good).hexdigest()}",
  ]
}}

provider "registry.terraform.io/example/other" {{
  version = "2.0.0"
  hashes = ["zh:{"0" * 64}"]
}}

provider "registry.terraform.io/example/absent" {{
  version = "3.0.0"
}}
"""
    main = """\
module "network" {
  source  = "example/network/aws"
  version = "1.0.0"
}
module "local" {
  source = "./modules/local"
}
module "git" {
  source = "git::https://git.example.org/modules/thing.git"
}
"""
    modules = {
        "Modules": [
            {"Key": "", "Dir": "."},
            {"Key": "network", "Dir": ".terraform/modules/network"},
        ]
    }
    mirror = "mirror/registry.terraform.io/example"
    files: dict[str, bytes | str] = {
        "infra/.terraform.lock.hcl": lock,
        "infra/main.tf": main,
        "infra/.terraform/modules/modules.json": json.dumps(modules),
        f"{mirror}/thing/terraform-provider-thing_1.0.0_linux_amd64.zip": good,
        f"{mirror}/other/terraform-provider-other_2.0.0_linux_amd64.zip": _provider_zip() + b"",
    }
    result = inspect(write(tmp_path / "d", files))
    [unit] = [u for u in result.analysis.units if u.kind.value == "terraform-environment"]
    assert unit.attributes["hashChecked"] == 1
    assert unit.attributes["unresolvable"] == ["registry.terraform.io/example/absent@3.0.0"]
    mismatch = [
        f.subject.display
        for f in findings_of(result)["environment.lock.hash-mismatch"]
        if f.result is Result.FAIL
    ]
    assert mismatch == [f"{mirror}/other/terraform-provider-other_2.0.0_linux_amd64.zip"]
    [modules_missing] = _failing(result, "iac.dependency.unresolvable").values()
    assert modules_missing["missing"] == [
        {"module": "git", "source": "git::https://git.example.org/modules/thing.git"}
    ]
    assert result.assessment.summary.verdict is Verdict.REFUSED


def test_ansible_requirements(tmp_path: Path) -> None:
    requirements = """\
collections:
  - name: community.general
    version: 8.0.0
  - name: example.packed
    version: 1.2.3
  - name: example.absent
roles:
  - name: example.webserver
  - src: https://git.example.org/roles/hardening.git
    name: hardening
"""
    files: dict[str, bytes | str] = {
        "ansible/requirements.yml": requirements,
        "ansible/collections/ansible_collections/community/general/MANIFEST.json": "{}",
        "ansible/example-packed-1.2.3.tar.gz": b"\x1f\x8b",
        "ansible/roles/example.webserver/tasks/main.yml": "- debug: {msg: hi}\n",
    }
    result = inspect(write(tmp_path / "d", files))
    [missing] = _failing(result, "iac.dependency.unresolvable").values()
    assert missing["missing"] == [
        {"collection": "example.absent", "version": ""},
        {"role": "hardening"},
    ]


def _archive(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive:
        for name, data in files.items():
            archive.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), data)
    return out.getvalue()


def test_manifests_inside_archives_are_checked(tmp_path: Path) -> None:
    """Deployment files usually arrive zipped. Their posture is checked there too; what needs the
    files beside them (vendored dependencies) is said to be not assessed."""
    chart = b"apiVersion: v2\nname: a\nversion: 1.0.0\ndependencies:\n  - {name: r, version: 1.0.0, repository: 'https://x'}\n"
    files: dict[str, bytes | str] = {
        "deploy.zip": _archive({"k8s/app.yaml": DEPLOYMENT.encode(), "chart/Chart.yaml": chart}),
        # what is baked into an image layer or installed as a dependency is not applied
        "site/node_modules/pkg/deploy.yaml": DEPLOYMENT,
    }
    result = inspect(write(tmp_path / "d", files))
    privileged = _failing(result, "iac.workload.privileged")
    assert list(privileged) == ["deploy.zip!/k8s/app.yaml#Deployment/web"]
    gaps = [
        f.subject.display
        for f in result.assessment.findings
        if f.rule == "iac.dependency.unresolvable" and f.result is Result.NOT_ASSESSED
    ]
    assert gaps == ["deploy.zip!/chart/Chart.yaml"]
    assert "iac.dependency.unresolvable" not in _failing_rules(result)


def _failing_rules(result) -> set[str]:  # type: ignore[no-untyped-def]
    return {f.rule for f in result.assessment.findings if f.result is Result.FAIL}


def test_damaged_provider_package_is_still_matched_by_its_sha256(tmp_path: Path) -> None:
    damaged = b"PK\x03\x04 this is not really a zip"
    lock = (
        'provider "registry.terraform.io/example/thing" {\n  version = "1.0.0"\n'
        f'  hashes = ["zh:{hashlib.sha256(damaged).hexdigest()}"]\n}}\n'
    )
    files: dict[str, bytes | str] = {
        "infra/.terraform.lock.hcl": lock,
        "mirror/registry.terraform.io/example/thing/terraform-provider-thing_1.0.0_linux_amd64.zip": damaged,
    }
    result = inspect(write(tmp_path / "d", files))
    [unit] = [u for u in result.analysis.units if u.kind.value == "terraform-environment"]
    assert (unit.attributes["resolved"], unit.attributes["hashChecked"]) == (1, 1)
    assert "inventory.handler.error" not in findings_of(result)
