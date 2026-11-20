# Security policy

superscrubber104 decides what may cross into a disconnected network. A flaw in it can let something through that should have been stopped, so security reports are welcome and taken seriously.

## Supported versions

superscrubber104 is pre-alpha and has no releases with long-term support yet. Fixes go to `main` and into the next release. Report against the latest release or `main`.

## Reporting a vulnerability

Please report privately, through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue for anything in the scope below.

A useful report says:

* what you expected superscrubber104 to do, and what it did;
* the smallest input that shows it: a file, an archive, a bundle, a policy. Build hostile samples from scratch; do not send real malware or anything taken from a non-public environment;
* the version or commit, the Python version and the operating system;
* the command and its output, including the exit code.

You can expect an acknowledgement within a week. This is a one-maintainer project, so a fix may take longer; you will hear how it is going. Credit is given in the fix and its advisory unless you would rather not be named.

## In scope

The guarantees superscrubber104 makes, and so the things that count as vulnerabilities when they fail:

| Guarantee | A vulnerability is |
|---|---|
| Nothing it inspects is executed | any input that makes superscrubber104 run, import, unpickle or load content: a model file, a package, an install script, a notebook |
| No network at runtime | any code path that opens a connection, resolves a name, or lets a scanner do so |
| Integrity and authenticity failures cannot be overridden | a bundle whose content, manifest, statement or signature was altered, and that `verify` does not refuse (exit 3); a replayed bundle, or one for another enclave, that is accepted; an approval, waiver or policy that turns a `final` finding into an accept |
| Fail closed | a crash, timeout or parser error that ends in an accept instead of a check error or "not assessed" |
| Nothing is silently dropped | a file, archive member or unit that crosses without being inventoried and hashed |
| Untrusted input is bounded | an input that makes superscrubber104 write outside its output directory (archive member names, symlinks), or expand or allocate without limit |
| Scanners are trusted only when pinned | a way to run a scanner, rule file or database that does not match its pins, or to plant a file the scanner loads unpinned |
| Evidence is not misleading | a report or summary that says a check passed when it did not run, or hides a blocker |

## Out of scope

* **Detection gaps.** A secret, a piece of malware or a vulnerability that a heuristic or a scanner does not recognise is a limitation, not a vulnerability. The known limits are listed at the end of each design document in [docs/design/](docs/design/README.md). Open an ordinary issue, unless the gap lets content past a `final` check.
* **The scanners themselves.** A flaw in ClamAV, Trivy, Semgrep or Bandit goes to that project. A flaw in how superscrubber104 runs them, pins them or reads their output is in scope.
* **A compromised receiving host or a compromised signing key.** superscrubber104 assumes the high side's host, its policy and its pinned keys are trustworthy ([threat model](docs/design/01-context-and-threat-model.md)).
* **Policy choices.** A site policy that allows something is the site's decision.

## How the code defends itself

The design rules that keep these guarantees are in [CONTRIBUTING.md](CONTRIBUTING.md). In short: static parsers only (never the libraries that load models), every decompression capped, archive member names never used as paths, every exception turned into a recorded check error, and `final` integrity rules that no policy can change. `tests/test_fail_closed.py` feeds every format values of the wrong type, and the test suite blocks the network.
