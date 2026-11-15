"""Built-in rules for agent and MCP assets, container images, and Python and JavaScript
packages and environments.

Final (not overridable) rules here are the ones where content does not match a digest it is
named or locked by: an image layer, a locked distribution, a wheel's own RECORD. Those are hash
mismatches. Everything else is a policy matter.
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
    final: bool = False,
    remediation: str = "",
) -> RuleSpec:
    return RuleSpec(rule_id, "1", title, severity, controls, rationale, remediation, final)


AGENTS = (
    _rule(
        "mcp.server.shell",
        "MCP server is launched through a shell",
        H,
        ("CM-7", "SI-3"),
        "A shell command line can run anything; the server is whatever the string says.",
    ),
    _rule(
        "mcp.server.runtime-fetch",
        "MCP server is fetched and installed when it starts",
        H,
        ("SC-7", "SR-3", "CM-11"),
        "npx, uvx, pipx and docker run resolve the server from a registry at launch: it will not "
        "work offline, and what runs is whatever the registry serves that day.",
        remediation="Vendor the server (package, wheel or image pinned by digest) and launch it "
        "from the local copy.",
    ),
    _rule(
        "mcp.server.remote",
        "MCP server is reached over the network",
        M,
        ("SC-7", "AC-4"),
        "A remote server is an egress path, and is unreachable on a disconnected network.",
    ),
    _rule(
        "mcp.config.credential",
        "Agent or MCP configuration contains a literal credential",
        H,
        ("IA-5",),
        "Credentials in configuration files travel with every copy. The value is not recorded.",
        remediation="Reference an environment variable or secret store instead.",
    ),
    _rule(
        "mcp.server.capability",
        "MCP server code can reach the shell, filesystem, network or credentials",
        M,
        ("CM-7", "AC-6"),
        "What a server's tools can do bounds what an agent using it can do. Found by static "
        "patterns in the server's source; severity depends on the capability.",
    ),
    _rule(
        "agent.prompt.injection",
        "Text aimed at the model contains injected instructions",
        H,
        ("SI-3", "SI-10"),
        "Tool descriptions, skills, instruction files and system prompts are read by the model; "
        "instructions hidden in them steer it.",
    ),
    _rule(
        "agent.prompt.hidden-characters",
        "Text aimed at the model contains invisible characters",
        M,
        ("SI-3", "SI-10"),
        "Zero-width, bidirectional and tag characters carry text a reviewer cannot see.",
    ),
    _rule(
        "agent.permissions.broad",
        "Agent permissions are broader than least privilege",
        H,
        ("AC-6", "CM-7"),
        "Allow-all modes, unrestricted shell access, automatic approval of tools or servers, and "
        "disabled confirmations remove the human check on what an agent does.",
    ),
    _rule(
        "agent.hook.command",
        "Agent hook runs a shell command",
        M,
        ("CM-7", "SI-3"),
        "Hooks run on agent events without a prompt; their commands are code that ships with "
        "the configuration.",
    ),
    _rule(
        "agent.hook.network",
        "Agent hook or skill script reaches the network",
        H,
        ("SC-7", "AC-4"),
        "A script that runs on agent events and makes network requests is an egress path.",
    ),
    _rule(
        "agent.skill.scripts",
        "Agent skill bundles executable scripts",
        L,
        ("CM-11", "SI-3"),
        "Skill scripts run when the agent uses the skill; they need the same review as any code.",
    ),
)

CONTAINERS = (
    _rule(
        "container.image.incomplete",
        "Container image refers to content that is not in the archive",
        H,
        ("CM-8", "SI-7"),
        "A missing configuration, manifest or layer makes the image unloadable.",
    ),
    _rule(
        "container.layer.digest-mismatch",
        "Image content does not match its digest",
        C,
        ("SI-7", "SR-11"),
        "Blobs are named by their sha256 and layers recorded by digest; a mismatch is corruption "
        "or substitution.",
        final=True,
    ),
    _rule(
        "container.user.root",
        "Container runs as root",
        M,
        ("CM-7", "AC-6"),
        "No USER is set, or it is root: a process escape lands with root privileges.",
        remediation="Set a non-root USER in the image.",
    ),
    _rule(
        "container.env.credential",
        "Container image sets a literal credential in its environment",
        H,
        ("IA-5",),
        "ENV values are visible to anyone with the image. The value is not recorded.",
    ),
)

PACKAGES = (
    _rule(
        "python.environment.unresolvable",
        "Locked Python requirement has no distribution in the delivery",
        H,
        ("CM-8", "SC-7"),
        "pip install --no-index would fail: someone will be tempted to fetch it informally.",
    ),
    _rule(
        "python.environment.hash-mismatch",
        "Python distribution does not match the hash it is locked to",
        C,
        ("SI-7", "SR-11"),
        "The file differs from what the lockfile was resolved against.",
        final=True,
    ),
    _rule(
        "python.requirements.unpinned",
        "Requirement is not pinned to an exact version",
        M,
        ("CM-8", "SR-3"),
        "An unpinned requirement resolves to whatever is newest at install time.",
    ),
    _rule(
        "python.requirements.unhashed",
        "Requirement is not pinned by hash",
        L,
        ("SI-7", "SR-11"),
        "Without hashes, a substituted distribution with the right name and version installs.",
    ),
    _rule(
        "python.requirements.remote-source",
        "Requirements point at a package index, URL or VCS",
        M,
        ("SC-7", "SR-3"),
        "Extra indexes enable dependency confusion; URL and VCS requirements fetch at install "
        "time and are not offline.",
    ),
    _rule(
        "python.package.pth-file",
        "Python package installs a .pth file that runs code",
        H,
        ("SI-3", "CM-7"),
        "Lines starting with 'import' in a .pth file run at every interpreter start.",
    ),
    _rule(
        "python.package.build-script",
        "Python source distribution runs code to build",
        M,
        ("SI-3", "CM-7"),
        "Installing an sdist runs its build backend (setup.py or a PEP 517 hook).",
        remediation="Transfer a wheel built in a controlled environment instead.",
    ),
    _rule(
        "python.wheel.record-mismatch",
        "Wheel contents do not match its RECORD",
        C,
        ("SI-7", "SR-11"),
        "RECORD lists every file in the wheel with its hash; a difference means the wheel was "
        "modified after it was built.",
        final=True,
    ),
    _rule(
        "python.environment.platform-mixed",
        "Wheelhouse targets more than one platform",
        L,
        ("CM-6",),
        "Wheels for different operating systems or Python versions; check that the target's "
        "are all present.",
    ),
    _rule(
        "npm.package.install-script",
        "npm package runs a script when installed",
        M,
        ("SI-3", "CM-7"),
        "preinstall, install and postinstall scripts (and native builds) run code on install.",
        remediation="Install with --ignore-scripts, or review the script.",
    ),
    _rule(
        "node.environment.unresolvable",
        "Locked npm package is not in the delivery",
        H,
        ("CM-8", "SC-7"),
        "Neither an installed copy in node_modules nor a package tarball is present; an "
        "offline install would fail.",
    ),
    _rule(
        "node.environment.integrity-mismatch",
        "npm package does not match the integrity it is locked to",
        C,
        ("SI-7", "SR-11"),
        "The package differs from what the lockfile was resolved against.",
        final=True,
    ),
    _rule(
        "node.lockfile.remote-source",
        "Lockfile resolves a package from git or a URL",
        M,
        ("SC-7", "SR-3"),
        "Git and URL dependencies are fetched at install time and bypass the registry.",
    ),
    _rule(
        "package.allowlist.unapproved",
        "Package is not on the approved list",
        H,
        ("SR-3", "CM-11"),
        "Only approved packages may cross; an unlisted name may be a typo-squat or a "
        "hallucinated dependency.",
    ),
    _rule(
        "source.minified",
        "Source is minified or generated",
        I,
        ("SA-11",),
        "Minified code cannot be meaningfully reviewed; it should come from a reviewed build.",
    ),
)

UPSTREAM = (
    _rule(
        "package.digest-mismatch",
        "Package does not match its own recorded digest",
        C,
        ("SI-7", "SR-11"),
        "An RPM's header digest or payload digest does not match the package: it was altered after "
        "it was built and signed.",
        final=True,
    ),
    _rule(
        "package.signature.invalid",
        "Package signature does not verify",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "The vendor's signature is from a pinned key but does not hold over the package.",
        final=True,
    ),
    _rule(
        "package.signature.untrusted",
        "Package is not signed by a key the policy pins",
        M,
        ("SR-4", "SR-11"),
        "Pin the vendor's key under trust.upstream with scope package.rpm.",
    ),
    _rule(
        "package.signature.missing",
        "Package is not signed",
        M,
        ("SR-4", "SR-11"),
        "Vendor packages are signed; an unsigned one was built elsewhere or had its signature "
        "removed.",
    ),
    _rule(
        "package.maintainer-scripts",
        "OS package runs scripts when installed",
        I,
        ("CM-7",),
        "Normal for OS packages and recorded for review: these scripts run as root on install.",
    ),
    _rule(
        "upstream.checksum-mismatch",
        "File differs from its publisher's checksum list",
        C,
        ("SI-7", "SR-11"),
        "The publisher's SHA256SUMS (or similar) lists a different hash for this file.",
        final=True,
    ),
    _rule(
        "upstream.signature.invalid",
        "Publisher's signature does not verify",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "A detached signature or signed checksum list from a pinned key does not hold.",
        final=True,
    ),
    _rule(
        "upstream.signature.untrusted",
        "Publisher's signature is from a key the policy does not pin",
        M,
        ("SR-4",),
        "Pin the publisher's key under trust.upstream (scope file.signed or file.checksums).",
    ),
)

MIRRORS = (
    _rule(
        "repo.metadata.digest-mismatch",
        "Repository index differs from its metadata",
        C,
        ("SI-7", "SR-11"),
        "repomd.xml or Release lists a different hash for this index: it is not the index the "
        "repository published.",
        final=True,
    ),
    _rule(
        "repo.content.digest-mismatch",
        "Package differs from the repository index",
        C,
        ("SI-7", "SR-11"),
        "The repository index lists a different hash for this package.",
        final=True,
    ),
    _rule(
        "repo.metadata.signature.invalid",
        "Repository metadata signature does not verify",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "The metadata is signed by a pinned key but the signature does not hold.",
        final=True,
    ),
    _rule(
        "repo.metadata.signature.untrusted",
        "Repository metadata is signed by a key the policy does not pin",
        M,
        ("SR-4", "SR-11"),
        "Pin the repository key under trust.upstream with scope repo.dnf or repo.apt.",
    ),
    _rule(
        "repo.metadata.unsigned",
        "Repository metadata is not signed",
        M,
        ("SR-4", "SR-11"),
        "Vendor repositories sign repomd.xml or Release; an unsigned copy cannot be traced to "
        "the vendor.",
    ),
    _rule(
        "repo.metadata.unlisted",
        "Repository index is not vouched for by the repository's metadata",
        M,
        ("SI-7", "SR-11"),
        "No metadata in the mirror lists this index with this hash, so what it says about "
        "packages is unverified.",
    ),
    _rule(
        "repo.metadata.malformed",
        "Repository metadata could not be read",
        M,
        ("SI-7",),
        "The file looks like repository metadata but does not parse.",
    ),
    _rule(
        "repo.metadata.expired",
        "Repository metadata is past its Valid-Until date",
        H,
        ("SI-2", "SR-11"),
        "apt refuses expired metadata unless told not to check; it is also a sign of a frozen "
        "or replayed mirror.",
    ),
    _rule(
        "repo.metadata.stale",
        "Repository metadata is older than the policy allows",
        M,
        ("SI-2", "RA-5"),
        "Set the allowed age with freshness.mirrors in the policy.",
    ),
    _rule(
        "repo.metadata.rollback",
        "Repository metadata is older than a snapshot already accepted",
        H,
        ("SI-2", "SI-7", "SR-11"),
        "A replayed or older mirror would undo security updates already imported.",
    ),
    _rule(
        "repo.content.missing",
        "Packages listed by the repository index are not in the delivery",
        L,
        ("CM-8", "SR-11"),
        "Installs that need them will fail on the high side. Normal for a curated subset; the "
        "count and a sample are recorded.",
    ),
    _rule(
        "repo.content.unlisted",
        "Mirror holds packages that no index lists",
        M,
        ("CM-7", "SR-11"),
        "Package managers will not see them, so they are either dead weight or were added "
        "after the metadata was made.",
    ),
    _rule(
        "repo.content.external",
        "Repository index points at the network",
        M,
        ("SC-7", "CM-7"),
        "An index entry with an absolute URL cannot be served offline.",
    ),
)

LOCKED = (
    _rule(
        "environment.lock.hash-mismatch",
        "Package differs from the hash its lockfile records",
        C,
        ("SI-7", "SR-11"),
        "go.sum, Cargo.lock, packages.lock.json or Gradle verification metadata records another "
        "hash for this package; the build tool would refuse it.",
        final=True,
    ),
    _rule(
        "environment.lock.unresolvable",
        "Locked dependencies are missing from the delivery",
        M,
        ("CM-8", "SR-11"),
        "An offline build or restore will fail on the high side.",
    ),
    _rule(
        "package.checksum-mismatch",
        "Package differs from the checksum recorded beside it",
        C,
        ("SI-7", "SR-11"),
        "A Maven .sha1/.sha256/.sha512, NuGet .nupkg.sha512, Go .ziphash, Gradle cache path or "
        "cargo .cargo-checksum.json records another hash.",
        final=True,
    ),
    _rule(
        "package.build-hooks",
        "Package runs code when it is built or installed",
        I,
        ("CM-7",),
        "Cargo build scripts and procedural macros, MSBuild targets, NuGet PowerShell scripts: "
        "recorded for review.",
    ),
)

IAC = (
    _rule(
        "iac.workload.privileged",
        "Workload runs privileged or can take over its host",
        H,
        ("AC-6", "CM-6", "CM-7"),
        "Privileged containers, the host PID namespace, container-runtime sockets and broad "
        "capabilities give the workload the node. Justify each or remove it.",
    ),
    _rule(
        "iac.workload.host-access",
        "Workload shares the host's network, IPC, devices or paths",
        M,
        ("AC-6", "CM-7", "SC-7"),
        "Host networking, host paths and host ports bypass the platform's isolation.",
    ),
    _rule(
        "iac.workload.root",
        "Workload is set to run as root",
        L,
        ("AC-6",),
        "Explicitly running as user 0 makes any container escape worse.",
    ),
    _rule(
        "iac.image.unpinned",
        "Image is referred to by tag, not digest",
        L,
        ("CM-2", "SI-7"),
        "A tag can be repointed after review; a digest names exactly the image that was checked.",
    ),
    _rule(
        "iac.dependency.unresolvable",
        "Infrastructure code fetches dependencies that are not in the delivery",
        M,
        ("CM-8", "SC-7"),
        "Helm chart dependencies, Terraform modules, Ansible collections and roles must be "
        "vendored to deploy offline.",
    ),
)

IDE = (
    _rule(
        "ide.extension.startup",
        "IDE extension activates on every start",
        I,
        ("CM-7",),
        "It runs whether or not it is used; recorded for review.",
    ),
    _rule(
        "ide.extension.proposed-api",
        "VS Code extension uses proposed APIs",
        L,
        ("CM-2",),
        "Proposed APIs only work on Insiders builds or with flags; the extension may not load.",
    ),
    _rule(
        "ide.extension.unresolvable",
        "IDE extension depends on extensions that are not in the delivery",
        M,
        ("CM-8",),
        "Extension dependencies, packs and required plugins must cross with it.",
    ),
)

VM = (
    _rule(
        "vm.format.mismatch",
        "Disk image is not the format its name or metadata declares",
        H,
        ("CM-6", "SI-7"),
        "Format confusion: an image declared raw that is really qcow2 makes the hypervisor follow "
        "its backing file. The format is always taken from the bytes.",
    ),
    _rule(
        "vm.image.incomplete",
        "Disk image depends on files outside itself",
        H,
        ("CM-8", "SI-7"),
        "Backing files, parent disks, external data files and missing extents: it will not boot as "
        "delivered, and the references can name paths on the source host. Flatten it "
        "(qemu-img convert) before packing.",
    ),
    _rule(
        "vm.image.encrypted",
        "Disk image is encrypted",
        M,
        ("SC-28",),
        "Nothing inside it can be inspected; the key must cross separately.",
    ),
    _rule(
        "vm.image.unclean",
        "Disk image was not closed cleanly or is marked corrupt",
        M,
        ("SI-7",),
        "Dirty or corrupt flags, an unreplayed log or a bad footer: run qemu-img check (and "
        "repair) on the source.",
    ),
    _rule(
        "vm.image.snapshots",
        "Disk image holds internal snapshots",
        L,
        ("CM-2",),
        "Snapshots keep earlier states of the disk, including data deleted since.",
    ),
    _rule(
        "vm.image.contents",
        "Guest filesystem contents inspected",
        I,
        ("SI-3", "CM-8"),
        "Images are never mounted; their contents are assessed only by a deep-inspection plugin.",
    ),
    _rule(
        "vm.metadata.mismatch",
        "Disk image differs from the metadata that describes it",
        C,
        ("SI-7", "SR-11"),
        "Glance os_hash_value, checksum or size, or an OVF file size, does not match.",
        final=True,
    ),
    _rule(
        "vm.image.check",
        "qemu-img found the image inconsistent",
        M,
        ("SI-7",),
        "qemu-img info disagrees with airlock's reading, or qemu-img check reports corruption or "
        "leaks.",
    ),
)

WINDOWS = (
    _rule(
        "authenticode.signature.invalid",
        "Windows package or binary does not match its Authenticode signature",
        C,
        ("SI-7", "SR-4", "SR-11"),
        "The content was changed after it was signed.",
        final=True,
    ),
    _rule(
        "authenticode.signature.untrusted",
        "Authenticode signature does not chain to a pinned root",
        M,
        ("SR-4", "SR-11"),
        "Pin the vendor's root certificates in plugins.osslsigncode.database/roots.pem.",
    ),
    _rule(
        "authenticode.signature.missing",
        "Windows package or binary is not signed",
        M,
        ("SR-4", "SR-11"),
        "Microsoft updates and most vendor installers are signed; an unsigned one was not "
        "published that way.",
    ),
)

SOFTWARE_RULES = (
    *AGENTS,
    *CONTAINERS,
    *PACKAGES,
    *UPSTREAM,
    *MIRRORS,
    *LOCKED,
    *IAC,
    *IDE,
    *VM,
    *WINDOWS,
)
