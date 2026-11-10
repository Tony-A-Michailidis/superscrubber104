# 12. VM images (OpenStack qcow2)

OpenStack exports are a primary use case (OpenStack + Ceph is a common platform for air-gapped appliances):

- **Never trust the extension or declared format.** Detect format from the header and compare with the declared `disk_format` in any Glance metadata. A raw image whose contents start with a qcow2 header (format confusion) is a finding.
- **`qemu-img info --output=json` and `qemu-img check`** (optional plugin, read-only; never mount images on the host kernel). Record virtual size, actual size, cluster size, compat level, dirty/corruption state.
- **Backing files are a blocker by default.** A qcow2 referencing a backing file is incomplete and can leak source host paths. Require flattening (`qemu-img convert`) before packing; report the chain if present.
- **Encryption:** detect LUKS-encrypted qcow2; content checks reported as "not assessed".
- **Glance metadata cross-check:** verify `os_hash_algo`/`os_hash_value` (usually sha512) and legacy `checksum` (md5). Record `os_distro`, `os_version`, `hw_*`, `img_signature*`, and verify Glance image signatures when the certificate is provided.
- **Compression and size:** compressed exports go through the safe archive path, with limits based on virtual size.
- **Optional deep inspection (libguestfs plugin, offline appliance mode):**
  - guest OS identity, and installed packages fed into the SBOM
  - local users, SSH `authorized_keys`, cloud-init user-data, bash history
  - embedded keys and credentials, unexpected services
  - **models and AI runtimes inside the image**, handled as above
