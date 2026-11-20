# Demo: sample output

What `python examples/demo/demo.py ~/airlock-demo` printed under WSL on AlmaLinux 10 with Python 3.12. The output is unedited, except that the working directory is shown as `/home/user/airlock-demo`. Key ids and some finding ids change from run to run. The rule count changes as rules are added.

What happens, in brief:
1. The low side packs a delivery, and the high side accepts it.
2. Someone with access to the media changes a model shard, adds an undeclared file and plants a malicious pickle.
3. The high side verifies again and refuses the bundle (exit 3).

The hash mismatch and the undeclared files are final, so no policy or approval can override them. The pickle is found by reading its opcodes, never by loading it. Scanners the demo does not configure are reported as not assessed rather than left out. [The quick start](../../docs/quickstart-wsl.md) explains how to run it. For a report on a real delivery of public projects (3.5 GB), see [real-delivery.md](real-delivery.md).

```text
Working in /home/user/airlock-demo

== 1. Keys: the build pipeline's packing key ==

$ airlock keygen -o keys --name pack --holder build-pipeline
  key id: ed25519:00c143f161be2c23bcfda5a4522cc87d02657b16c2c47780c68ccc6b09ae1018
  
  To trust this key, add it to the receiving side's policy:
  ... (9 more lines)
  [exit 0]

== 2. Low side: pack the delivery ==

$ airlock pack delivery --request request.yaml --key keys/pack.key --policy low/policy.yaml -o bundle
  WARN            kb.embedding-model.unrecorded  [e63d460f69e659dc]
                  knowledge-base:rag/docs: Knowledge base does not record which embedding model built it
  WARN            not assessed: malware.detected  [f6490e189d646738]
                  bundle: the check did not run: no malware scanner is configured (plugins.clamav)
  WARN            not assessed: sast.finding  [a1e2942baaf74d8e]
                  bundle: the check did not run: no static analysis scanner is configured (plugins.semgrep or plugins.bandit)
  WARN            not assessed: vuln.component.known  [0cd93b81a6d98aa3]
                  bundle: the check did not run: no vulnerability scanner is configured (plugins.trivy)
  
  62 of 212 rules exercised, 255 checks passed; findings: 0 block, 0 need approval, 4 warn, 1 allowed
  verdict: PASSED
  manifest: sha256:7ede3a432467008d951c1d14d24605ccb08aa6e4f5abe3ead889d812cd10ab9c
  ... (1 more lines)
  [exit 0]

== 3. High side: verify the bundle as it arrived ==

$ airlock verify bundle --policy high/policy.yaml --state high/state --out import-1
  WARN            kb.embedding-model.unrecorded  [e63d460f69e659dc]
                  knowledge-base:rag/docs: Knowledge base does not record which embedding model built it
  WARN            not assessed: malware.detected  [f6490e189d646738]
                  bundle: the check did not run: no malware scanner is configured (plugins.clamav)
  WARN            not assessed: sast.finding  [a1e2942baaf74d8e]
                  bundle: the check did not run: no static analysis scanner is configured (plugins.semgrep or plugins.bandit)
  WARN            not assessed: vuln.component.known  [0cd93b81a6d98aa3]
                  bundle: the check did not run: no vulnerability scanner is configured (plugins.trivy)
  
  78 of 212 rules exercised, 314 checks passed; findings: 0 block, 0 need approval, 4 warn, 1 allowed
  verdict: PASSED
  wrote:    import-1/assessment.verify.json
  ... (3 more lines)
  [exit 0]

$ airlock report import-1 --format html -o import-1/report.html
  wrote:    import-1/report.html
  [exit 0]

$ airlock report import-1 --format cyclonedx -o import-1/sbom.cdx.json
  wrote:    import-1/sbom.cdx.json
  [exit 0]

$ airlock report import-1 --format oscal -o import-1/oscal.json
  wrote:    import-1/oscal.json
  [exit 0]

== 4. In transit: someone with access to the media tampers with the bundle ==
  changed 16 bytes of bundle/payload/models/tiny-chat/model-00002-of-00002.safetensors
  added app/patch-notes.txt, which no one declared
  added models/tiny-chat/training_args.bin, a pickle that would run a shell command

== 5. High side: verify the tampered bundle ==

$ airlock verify bundle --policy high/policy.yaml --state high/state --out import-2
  REFUSE          integrity.entry.unexpected  [28acb79bd69f8e44]
                  app/patch-notes.txt: Payload contains content that is not in the manifest
  REFUSE          integrity.entry.unexpected  [24ac6f7ab16e6160]
                  models/tiny-chat/training_args.bin: Payload contains content that is not in the manifest
  REFUSE          integrity.hash.mismatch  [1f3451731f1bf6d0]
                  models/tiny-chat/model-00002-of-00002.safetensors: Content does not match the manifest
  REFUSE          replay.bundle.already-accepted  [c501d5f35b1d7013]
                  bundle: A bundle with this id and signed statement was already accepted
  BLOCK           model.pickle.dangerous-import  [d5085f50ae1334e7]
                  models/tiny-chat/training_args.bin: Pickle imports a dangerous callable
                  approvals: 0 of 2 required
  NEEDS APPROVAL  model.format.code-capable  [04c6860cbcbadba6]
                  models/tiny-chat/training_args.bin: Model or data file can run code when loaded
                  approvals: 0 of 1 required
  WARN            kb.embedding-model.unrecorded  [e63d460f69e659dc]
                  knowledge-base:rag/docs: Knowledge base does not record which embedding model built it
  WARN            not assessed: malware.detected  [f6490e189d646738]
                  bundle: the check did not run: no malware scanner is configured (plugins.clamav)
  WARN            not assessed: sast.finding  [a1e2942baaf74d8e]
                  bundle: the check did not run: no static analysis scanner is configured (plugins.semgrep or plugins.bandit)
  WARN            not assessed: vuln.component.known  [0cd93b81a6d98aa3]
                  bundle: the check did not run: no vulnerability scanner is configured (plugins.trivy)
  
  82 of 212 rules exercised, 316 checks passed; findings: 5 block, 1 need approval, 4 warn, 2 allowed
  verdict: REFUSED - an integrity or authenticity check failed; this cannot be overridden
  wrote:    import-2/assessment.verify.json
  wrote:    import-2/analysis.verify.json
  wrote:    import-2/request.yaml
  wrote:    import-2/receipt.json
  [exit 3]

$ airlock report import-2 --format md -o import-2/report.md
  wrote:    import-2/report.md
  [exit 0]

$ airlock report import-2 --format html -o import-2/report.html
  wrote:    import-2/report.html
  [exit 0]

== Result ==
  tampered shard   caught: integrity.hash.mismatch on models/tiny-chat/model-00002-of-00002.safetensors
  undeclared file  caught: integrity.entry.unexpected on app/patch-notes.txt
  pickle payload   caught: model.pickle.dangerous-import on models/tiny-chat/training_args.bin
  clean import accepted (exit 0); tampered import refused (exit 3)
  and the ledger noticed the same signed bundle arriving a second time
  reports: /home/user/airlock-demo/import-1/ and /home/user/airlock-demo/import-2/
```

