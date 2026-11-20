# superscrubber104 crosses its own airlock

A tool that decides what may enter a disconnected network has to get there itself, and it should not get an easier path than everything else. [`self-transfer.sh`](self-transfer.sh) moves superscrubber104 from a connected machine to one with no network, the way it moves any delivery: packed, signed, checked on arrival.

```console
$ examples/self-transfer/self-transfer.sh /tmp/self-transfer
```

It needs bash, Python 3.11 or later with `venv`, `sha256sum`, and network access for the low side. CI runs it on every push.

## The trust chain

The first crossing has a bootstrap problem: there is no superscrubber104 on the high side yet to verify the bundle it arrives in. So the first install is checked with tools the high side already has, and superscrubber104 checks everything after that.

| Step | Where | Checked by | Against |
|---|---|---|---|
| 1 | low | `pip download --only-binary=:all:` | exactly the versions the low side runs, as wheels: nothing is built on the high side |
| 2 | low | a lock with every wheel's hash, and `SHA256SUMS` over the lock and the wheels | |
| 3 | low | `superscrubber104 pack`, signed with the pipeline's key | the low side's policy |
| 4 | out of band | the digest of `SHA256SUMS` (a short string: read it over the phone, or print it) and the public key | |
| 5 | high, no network | `sha256sum` | the out-of-band digest, then every file against `SHA256SUMS` |
| 6 | high, no network | `pip install --no-index --require-hashes` | the lock: pip refuses any wheel whose hash differs |
| 7 | high, no network | the superscrubber104 just installed: `verify` | the pinned public key, the signed statement, a full re-analysis |
| later | high | the installed superscrubber104 verifies each new version's bundle before it is installed | the pinned key and the ledger (replay, ordering) |

Step 7 on its own proves little: a tampered superscrubber104 could approve itself. It is there because steps 5 and 6 have already established that the installed copy is the one that was packed. What step 7 adds is the evidence record for the tool itself (inventory, licences, signature, receipt in the ledger), the same record every other delivery gets. From then on the trust runs forward: version n verifies version n+1.

What the out-of-band digest protects against is an attacker who controls the media. Someone who can also change the digest the high side expects (the phone call, the printed sheet) can substitute anything, and no tool can detect that; the same is true of the public key that travels with it.

## A run

From a run on AlmaLinux 10 (WSL), with Python 3.12. The high side runs inside `unshare -rn`, a network namespace with only a loopback interface, which is down; the script checks that it really cannot connect before it continues.

```console
== 2. Low side: build the delivery (superscrubber104 and the wheels it depends on) ==
cffi==2.1.1 --hash=sha256:c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf
click==8.5.1 --hash=sha256:8bb5376d2006950386f8c6427613334a2acadc5f559cb80e638d00b4df957e37
cryptography==50.0.2 --hash=sha256:9dab55f57c74c3cad24c323bacbbd04be4705ba6eb0d92e920b1fc4837ed5079
pycparser==3.12 --hash=sha256:a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e
pyyaml==6.0.3 --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc
superscrubber104==0.0.1 --hash=sha256:f69b508a65ee5e5689cb6f7d9668db17e5b77f4c67ba522c23ac2848722cb564
SHA256SUMS digest, to send out of band: 0da427d624885c3f2455e980e52a2964c53ddc4bd3720f5f1f570c1fb874bc90

== 4. Low side: superscrubber104 packs itself ==
31 of 212 rules exercised, 3245 checks passed; findings: 0 block, 0 need approval, 3 warn, 0 allowed
verdict: PASSED
manifest: sha256:89da93b3e05e19d8364ee285b117c0a075f562099923c3c756053d9ae3d088f9
bundle:   bundle (signed by ed25519:d29a7c3fb21f4b461396937618d21e1b9c3e0c05ffe701d7d75e572baf056d15)
[pack exit 0]

== 6. High side, with no network ==
no network: pypi.org cannot be reached

-- 6a. check the first crossing with standard tools --
expected: 0da427d624885c3f2455e980e52a2964c53ddc4bd3720f5f1f570c1fb874bc90
actual:   0da427d624885c3f2455e980e52a2964c53ddc4bd3720f5f1f570c1fb874bc90
every file matches SHA256SUMS

-- 6b. install from the bundle, offline, every wheel checked against its hash --
superscrubber104, version 0.0.1

-- 6c. the installed superscrubber104 verifies the signed bundle it came in --
47 of 212 rules exercised, 3279 checks passed; findings: 0 block, 0 need approval, 3 warn, 0 allowed
verdict: PASSED
[verify exit 0]

== 7. The same media, altered in transit: the first-crossing checks refuse it ==
appended one byte to wheels/cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl
wheels/cryptography-50.0.2-cp311-abi3-manylinux_2_34_x86_64.whl: FAILED
sha256sum: WARNING: 1 computed checksum did NOT match
ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE. If you have updated the package versions, please update the hashes. Otherwise, examine the package contents carefully; someone may have tampered with them.
pip refused the altered wheel; nothing was installed
```

The three warnings are the scanners this example does not configure (malware, vulnerabilities, static analysis), recorded as not assessed. A real crossing configures them on the low side, as [docs/scanners.md](../../docs/scanners.md) describes, and carries the scanners and their databases across the same way.

The first run of this script found a false positive in superscrubber104: `cryptography`'s stable-ABI wheel (`cp311-abi3`) was counted as a second Python version beside the `cp312` wheels, so any environment with `cryptography` in it was reported as mixing platforms.

## Limits

* The wheels are for the platform and Python that ran the low side. For another target, add `--platform`, `--python-version` and `--implementation` to the `pip download` line, and run the high side there.
* The high side needs Python itself. Python is part of the operating system's own transfer (an OS mirror or image), not of this one.
* `unshare -rn` needs unprivileged user namespaces. Where the kernel does not allow them, the script says so and relies on `pip --no-index` alone; `REQUIRE_NO_NETWORK=1` makes that an error instead, as CI does.
