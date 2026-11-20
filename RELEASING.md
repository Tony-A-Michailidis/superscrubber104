# Releasing

## Making a release

1. Move the `[Unreleased]` entries in [CHANGELOG.md](CHANGELOG.md) into a section for the new version, with the date, and update the links at the bottom.
2. Set `__version__` in `src/superscrubber104/__init__.py`.
3. Commit, push, and wait for CI to pass (including the self-transfer job).
4. Tag the commit and push the tag:

   ```console
   $ git tag -a v0.1.0 -m "superscrubber104 0.1.0"
   $ git push origin v0.1.0
   ```

The [release workflow](.github/workflows/release.yml) then runs the tests again, checks that the tag matches `__version__` and that the changelog has a section for it, builds the wheel and the sdist, and publishes a GitHub release with:

* `superscrubber104-X.Y.Z-py3-none-any.whl` and `superscrubber104-X.Y.Z.tar.gz`;
* `SHA256SUMS` over both;
* a signed SLSA build-provenance attestation for both, stored in the repository's attestations;
* the changelog section as release notes.

Releases are built only by the workflow, never on a developer's machine: a local build can pick up untracked files, and it has no provenance.

## Checking a release

Download the files from the release page, then:

```console
$ sha256sum --check SHA256SUMS
$ gh attestation verify superscrubber104-0.1.0-py3-none-any.whl --repo Tony-A-Michailidis/superscrubber104
```

The attestation proves the wheel was built by this repository's release workflow from the tagged commit. For a disconnected site, run these checks on the connected side, then carry the wheel across as [examples/self-transfer/](examples/self-transfer/README.md) shows.

## Rebuilding a release

The build is reproducible, so a release can be checked without trusting the workflow at all:

```console
$ git clone https://github.com/Tony-A-Michailidis/superscrubber104 && cd superscrubber104
$ git checkout v0.1.0
$ python -m venv /tmp/build && /tmp/build/bin/pip install build==1.6.1
$ SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" /tmp/build/bin/python -m build --outdir /tmp/dist
$ cd /tmp/dist && sha256sum *
```

The hashes should match `SHA256SUMS`. Both build tools are pinned exactly for this reason: `build` here and in the workflow, and the build backend (`hatchling`) in `pyproject.toml`.
