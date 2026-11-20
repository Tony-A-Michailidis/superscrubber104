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
* the changelog section as release notes.

Releases are built only by the workflow, never on a developer's machine: a local build can pick up untracked files.

There is no signed build-provenance attestation: GitHub offers those for private repositories only on GitHub Enterprise Cloud. Rebuilding the release, below, is the check instead, and a stronger one: it does not trust the workflow at all.

## Checking a release

Download the files from the release page and run `sha256sum --check SHA256SUMS`. That shows the files are the ones the workflow published. To show they are what the tagged source produces, rebuild them. For a disconnected site, do both on the connected side, then carry the wheel across as [examples/self-transfer/](examples/self-transfer/README.md) shows.

## Rebuilding a release

The build is reproducible, so anyone with access to the source can check a release:

```console
$ git clone https://github.com/Tony-A-Michailidis/superscrubber104 && cd superscrubber104
$ git checkout v0.1.0
$ python -m venv /tmp/build && /tmp/build/bin/pip install build==1.6.1
$ SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" /tmp/build/bin/python -m build --outdir /tmp/dist
$ cd /tmp/dist && sha256sum *
```

The hashes should match `SHA256SUMS`. Both build tools are pinned exactly for this reason: `build` here and in the workflow, and the build backend (`hatchling`) in `pyproject.toml`.
