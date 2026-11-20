# Scale test

superscrubber104 hashes and parses every file by streaming it, so its memory should not depend on how big the files are. [`scale.py`](scale.py) checks that, and measures how time and memory grow with the size of a delivery and with the number of files in it.

```console
$ python examples/scale/scale.py /tmp/scale --small 10000 --members 10000 --large-gib 16 --shard-gib 16
```

It builds a synthetic delivery: small Python and Markdown files in nested directories, model weights as safetensors shards filled with random bytes (incompressible, so nothing is faster than with real weights), a zip with many members and a gzipped tar. Then it runs `keygen`, `pack --link` and `verify`, each in its own process, and prints the wall time, the throughput and the peak resident memory of each. It needs Linux or WSL, and disk space for the delivery.

## Results

On a laptop: Intel Core i7-10850H (12 threads), 32 GB of memory, AlmaLinux 10 under WSL 2, Python 3.12, superscrubber104 0.1.0. No scanners configured.

| Run | Delivery | Step | Wall time | Throughput | Peak memory |
|---|---|---|---|---|---|
| A | 1 GiB of weights in one file, 10,000 small files, a zip of 10,000 members | pack | 16 s | 63 MiB/s | 146 MiB |
| | | verify | 13 s | 77 MiB/s | 141 MiB |
| B | **16 GiB of weights in one file**, the same small files and zip | pack | 71 s | 232 MiB/s | 146 MiB |
| | | verify | 70 s | 233 MiB/s | 140 MiB |
| C | 1 GiB of weights, **100,000 small files, a zip of 100,000 members** | pack | 86 s | 12 MiB/s | 979 MiB |
| | | verify | 82 s | 13 MiB/s | 989 MiB |

Every run passed with the same findings: one licence approval (the default policy asks for every licence) and warnings for the checks that were not configured. Each recorded every Markdown file as unclassified (allowed), as superscrubber104 has no handler for plain text documents and never drops a file silently.

## What it shows

* **Memory does not grow with file size.** A 16 GiB file and a 1 GiB file need the same memory (146 MiB): weights are hashed and their headers parsed by streaming, never loaded.
* **Large files go at about 230 MiB/s**, hashing and parsing included, on one core. A 70 GB model takes about five minutes to pack and five to verify.
* **Memory grows with the number of files and archive members**, by about 5 KiB each: the inventory, the findings and the evidence for every file are kept until the signed statement is written. 200,000 files and members took under 1 GiB. A delivery of millions of small files (a full package mirror) would need several gigabytes; split it into several bundles, or into volumes and deltas ([doc 26](../../docs/design/26-volumes-and-deltas.md)).
* **Small files are bound by the per-file work** (about 2,300 files and members a second), not by bytes.

## Limits

* One machine, one run of each; times will vary with the disk and the cache. Run it on the machine that will do the transfer.
* No scanners: ClamAV and Trivy add their own time, which for ClamAV is roughly that of reading every byte again (13 minutes for 3.3 GB in [the real delivery](../demo/real-delivery.md#with-real-scanners)).
* `pack --link` hard-links the files; without it, `pack` also copies every byte into the bundle.
