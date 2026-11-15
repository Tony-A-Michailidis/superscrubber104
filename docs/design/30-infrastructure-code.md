# 30. Infrastructure code

> **Status: implemented.** Spec: [§4](04-artifact-coverage.md) (infrastructure code, containers), [§13](13-checks-and-controls.md) (checks and controls). Image references against the delivery are the offline check's ([23](23-offline-and-runtime.md)).

Infrastructure code is what will run with the most privilege on the high side. The handler (`airlock/handlers/iac.py`) answers three questions for each file. What will this workload be allowed to do to its host? Is every image named exactly? What will deploying it try to fetch?

| File | Recognised by | Checked |
|---|---|---|
| Kubernetes manifests | YAML with `apiVersion` and `kind` (multi-document, `kind: List`) | posture of every pod spec (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob, ReplicationController), image pinning |
| Compose files | `compose.yaml`, `docker-compose*.yml` | posture of every service, image pinning |
| Helm charts | `Chart.yaml` (with `Chart.lock`, or the v2 `requirements.yaml`/`requirements.lock`) | dependencies vendored under `charts/`; templates recorded as not rendered |
| Terraform | `*.tf`, `.terraform.lock.hcl`, provider packages in a filesystem mirror | remote modules installed in `.terraform/modules`; provider hashes |
| Ansible | `requirements.yml` | collections and roles installed alongside |

## 30.1 Workload posture

| Rule | Severity | Kubernetes | Compose |
|---|---|---|---|
| `iac.workload.privileged` | high | `privileged`, `allowPrivilegeEscalation: true`, `hostPID`, a hostPath to a container-runtime socket, capabilities `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_RAWIO`, `DAC_READ_SEARCH`, `BPF` | `privileged`, `pid: host`, `userns_mode: host`, runtime socket mounts, the same capabilities |
| `iac.workload.host-access` | medium | `hostNetwork`, `hostIPC`, other hostPaths, `hostPort`, `NET_ADMIN`, `NET_RAW`, `SYS_TIME`, `SYS_BOOT` | `network_mode: host`, `ipc: host`, bind mounts of `/`, `/etc`, `/proc`, `/sys` and similar, devices |
| `iac.workload.root` | low | `runAsUser: 0`, `runAsNonRoot: false` (pod or container) | `user: root` or `0` |
| `iac.image.unpinned` | low | images by tag, by `latest`, or with no tag | same |

There is one finding per rule and workload. The subject locates the workload (`deploy/app.yaml#Deployment/web`), and the detail lists every setting found. Some workloads legitimately need these settings, such as node exporters and CNI agents. The finding is the record that someone looked and approved, through a waiver or approval naming the workload.

Only explicit settings are reported. An unset `runAsNonRoot` is not, because most images set their user, and flagging every workload would bury the ones that ask for root.

## 30.2 Dependencies fetched at deploy time

`iac.dependency.unresolvable` (medium) lists what is missing, with `tool` as an attribute so a policy can treat Helm, Terraform and Ansible differently.

* **Helm**: each dependency must be in `charts/` as `<name>-<version>.tgz` (the version from `Chart.lock` when there is one) or as an unpacked `charts/<name>/`. A `file://` repository must point at a chart in the delivery.
* **Terraform**: modules whose `source` is not a local path need an entry in `.terraform/modules/modules.json` (what `terraform init` writes).
* **Ansible**: collections need `collections/ansible_collections/<ns>/<name>/` (or `../collections`) or a `<ns>-<name>-<version>.tar.gz` beside the requirements file. Roles need `roles/<name>/` with `meta/main.yml` or `tasks/main.yml`. Git and URL sources must have been installed.

## 30.3 Terraform providers

`.terraform.lock.hcl` is a lockfile for the shared assembler ([29.1](29-more-ecosystems.md)), producing unit `terraform-environment`. `zh:` hashes are the sha256 of the provider zip (as in the provider's `SHA256SUMS`). `h1:` is the same dirhash as Go's, over the zip's files. Provider packages in a **packed** filesystem mirror (`<host>/<namespace>/<type>/terraform-provider-<type>_<version>_<os>_<arch>.zip`) are hashed both ways. **Unpacked** providers (`<host>/<namespace>/<type>/<version>/<os>_<arch>/terraform-provider-…`) resolve by name and version, but their `h1:` covers the whole directory, which one file cannot see. They are counted as `hashUnverifiable`. Checked against HashiCorp's `null` 3.2.2: the zip's sha256 equals its published `SHA256SUMS` entry. Components: `pkg:terraform/<address>@<version>`.

## 30.4 Templates and YAML

Helm templates are not rendered. Rendering needs the chart's values and Helm's template functions, and it is the operator's choice of values that matters. Template files are classified `helm.template`, and the chart records **once** that its workloads were not assessed, with the fix: deliver the output of `helm template` and it is checked like any manifest.

Compose files and manifests use anchors and merge keys, so they are read with aliases allowed, within a budget: a document whose fully expanded node count exceeds 200,000 is refused. That gives the protection against alias bombs without refusing ordinary files. Model cards and other YAML keep the stricter no-aliases loader. A bare `=` (YAML 1.1's value type, found in real CRDs) reads as the string `=`.

## 30.5 Tests and limits

`tests/test_iac.py` covers:

* a Deployment, CronJob and Service with every posture class;
* Compose with anchors and merge keys;
* the alias budget;
* Helm dependencies from a lock, an unpacked subchart, `file://` and a missing OCI chart;
* Terraform packed providers (match, mismatch, absent) and modules;
* Ansible collections (installed, packed, absent) and roles.

Not covered:

* rendering of Helm templates, Kustomize overlays and Jsonnet;
* OPA/Gatekeeper or Kyverno policy evaluation, which is better done by those tools on the high side;
* Terraform `backend` settings;
* `.tfvars`;
* CloudFormation and ARM/Bicep templates (inventoried and scanned as configuration).
