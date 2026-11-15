# 32. VM images and appliances

> **Status: implemented.** Spec: [§10](10-vm-images.md) (VM images), [§13](13-checks-and-controls.md). Operator guide for the optional `qemu-img` plugin: [docs/scanners.md](../scanners.md).

Disk images are the largest and most opaque things that cross. airlock reads their headers and metadata (`formats/disk.py`, `handlers/vm.py`) and never mounts them or runs anything from them. The format is always taken from the bytes, never from the name.

## 32.1 Formats

| Format | Recognised by | What is read |
|---|---|---|
| qcow2 (v2, v3) | `QFI\xfb` | virtual size, cluster size, backing file and its format, encryption (AES, LUKS), dirty and corrupt bits, the external data file extension, internal snapshots |
| VMDK | `KDMV` sparse header, or a `# Disk DescriptorFile` text descriptor | the descriptor (embedded or standalone): create type, extents, `parentCID`/`parentFileNameHint`, adapter, the unclean-shutdown flag, compression |
| VHD | `conectix` footer (at the end, or copied at the start of dynamic disks) | disk type (fixed, dynamic, differencing), size, the parent's name, footer checksum, saved state |
| VHDX | `vhdxfile` | the current header (log pending = unclean), region table, metadata: virtual size, block size, `HasParent`, parent locator |
| raw | `.img`, `.raw`, `.dd`, `.disk` names | MBR or GPT partitions (types named, LUKS partitions noted), a LUKS header at the start |
| ISO 9660 | `CD001` at sector 16 | volume and system identifiers, size, El Torito boot record |

A qcow2 named `.img` is normal: cloud images are distributed that way. A name that clearly says another format (`.raw`, `.vhd`, `.vmdk`, `.qcow2`, `.iso`) and bytes that disagree are `vm.format.mismatch` (high). That is format confusion: a hypervisor told "raw" that finds a qcow2 header may follow its backing file to read the host.

## 32.2 Findings per image

| Rule | Severity | When |
|---|---|---|
| `vm.image.incomplete` | high | backing file, parent disk, external data file, VMDK extents not beside the descriptor, OVF-referenced files missing. It will not boot as delivered, and the names can be paths on the source host, so flatten it first (`qemu-img convert -O qcow2`). |
| `vm.image.encrypted` | medium | qcow2 encryption, a LUKS volume, a LUKS partition: nothing inside can be inspected, and the key has to cross separately |
| `vm.image.unclean` | medium | qcow2 dirty or corrupt, VMDK unclean shutdown, VHDX log not replayed, VHD footer checksum wrong or saved state |
| `vm.image.snapshots` | low | qcow2 internal snapshots: earlier states of the disk, including data deleted since |
| `vm.image.contents` | not assessed | always: guest filesystems are never mounted. The reason says whether the image is encrypted or simply not inspected. A deep-inspection plugin (libguestfs in an appliance) is where guest packages, users, keys and models would come from (see limits) |
| `vm.image.check` | medium | the `qemu-img` plugin disagrees with airlock's reading, or `qemu-img check` reports corruption or leaks; not assessed when the plugin is not configured |

Each image is a `vm-image` unit with its format, size, dependencies, encryption and partitions, plus the Glance properties when metadata travels with it.

## 32.3 Appliances: OVA and OVF

* **OVA** (a tar): one streaming pass hashes every member with SHA-1, SHA-256 and SHA-512 and keeps the descriptor and manifest. Then every `.mf` line (`SHA256(file)= …`) is compared, and a difference is `upstream.checksum-mismatch` (final). Every file the `.ovf` references must be in the archive with its declared size: missing files are `vm.image.incomplete`, a wrong size is `vm.metadata.mismatch` (final). The disks inside are then read as nested artifacts like any other image. A `.cert` (signed manifest) is recorded, not verified (see limits).
* **Unpacked OVF** directories: the same checks against files beside the descriptor, with `.mf` lines verified through the delivery.

## 32.4 OpenStack Glance metadata

The output of `openstack image show -f json` saved beside the image (`<image>.json`, or any JSON naming the image in `name`) is checked against the image:

* `os_hash_algo`/`os_hash_value` (normally sha512), the legacy md5 `checksum` and `size`, in one pass: a difference is `vm.metadata.mismatch` (final), and a match gives a `glance` verification at checksum level;
* `disk_format` against the bytes: `vm.format.mismatch`;
* `img_signature` with `img_signature_hash_method` and `img_signature_key_type` (RSA-PSS, ECC, DSA): verified against certificates pinned in `trust.upstream` with scope `vm.glance` (the certificate Barbican holds for `img_signature_certificate_uuid`, exported and pinned). A verified signature gives a `glance-signature` verification at signature level. No pinned certificate is `upstream.signature.untrusted`; a signature that does not hold is `upstream.signature.invalid` (final).

`os_distro`, `os_version`, `hw_*` properties, `min_disk`, `min_ram` and the architecture are kept on the unit.

## 32.5 The qemu-img plugin

Optional and pinned like every scanner. It runs `qemu-img info` and `check` with the format given (`-f`, never probed) and `-U` (no locks), and compares their answers with airlock's. See [docs/scanners.md](../scanners.md).

## 32.6 Validation, tests and limits

Checked against a real CirrOS 0.6.2 qcow2 (v3, 112 MiB virtual, Glance md5 and sha512 matched) and Alpine's virt ISO (bootable, volume ID read). `tests/test_vm.py` builds every format's headers in `tests/vm_fixtures.py` and covers:

* each finding;
* format confusion;
* an OVA with a bad manifest line and a missing disk, and a clean unpacked export;
* Glance hashes, format and an RSA-PSS signature against a pinned certificate;
* the qemu-img plugin, configured and not.

Not done:

* deep inspection of guest filesystems (libguestfs in an appliance: guest OS, packages into the SBOM, users, keys, cloud-init, models). This needs a sandboxed plugin and is the natural next step;
* OVA `.cert` verification;
* VDI, QED and Parallels formats (inventoried as unclassified);
* compressed qcow2 clusters are not decompressed (nothing reads guest data);
* virtual-size-based expansion limits for compressed exports.
