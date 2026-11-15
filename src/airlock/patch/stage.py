"""Downgrade protection for ``airlock patch stage``.

A bundle that carries an older version of a package than the host already runs would roll back a
fix. Staging is refused unless the operator gives a justification, which is kept in the stage
report and so, by digest, in the ledger.
"""

from collections.abc import Callable

from airlock.formats.deb import deb_vercmp
from airlock.formats.rpm import compare_evr
from airlock.patch.inventory import Inventory
from airlock.stage import StageError
from airlock.verify import Verified


def downgrades(verified: Verified, inventory: Inventory) -> list[str]:
    installed = inventory.installed()
    found = []
    for artifact in verified.analysis.artifacts:
        rpm = artifact.metadata.get("rpm")
        deb = artifact.metadata.get("deb")
        compare: Callable[[str, str], int]
        if isinstance(rpm, dict) and inventory.os.family == "rpm":
            name, version, arch = (
                str(rpm.get("name")),
                str(rpm.get("evr")),
                str(rpm.get("arch", "")),
            )
            compare = compare_evr
        elif isinstance(deb, dict) and inventory.os.family == "deb":
            name, version = str(deb.get("name")), str(deb.get("version"))
            arch = str(deb.get("arch", ""))
            compare = deb_vercmp
        else:
            continue
        for package in installed.get(name, []):
            same_arch = not arch or not package.arch or arch in (package.arch, "noarch", "all")
            if same_arch and compare(version, package.version) < 0:
                found.append(f"{name} {package.version} installed, bundle has {version}")
    return sorted(set(found))


def downgrade_check(
    inventory: Inventory, justification: str | None
) -> Callable[[Verified], str | None]:
    def check(verified: Verified) -> str | None:
        found = downgrades(verified, inventory)
        if found and not justification:
            raise StageError(
                "refusing to downgrade: "
                + "; ".join(found[:20])
                + " (use --allow-downgrade with a justification)"
            )
        return f"{justification}: {'; '.join(found)}" if found else None

    return check
