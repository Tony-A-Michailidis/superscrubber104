# 24. Model signatures and behavioural verification

> **Status: implemented** (brought forward from 1d at the owner's request). Spec: the provenance item of [§7](05-model-packages.md) (OpenSSF model signing), [§11](09-behavioural-verification.md) (`superscrubber104 eval`).

Two ways to know that the model on the high side is the model its publisher released and that it behaves as tested: a cryptographic one (the publisher's signature over every file) and a behavioural one (the same prompts, the same answers).

## 24.1 Model signatures

[OpenSSF model signing](https://github.com/sigstore/model-transparency) writes a `model.sig` Sigstore bundle next to the model. Its DSSE envelope holds an in-toto statement (`predicateType: https://model_signing/signature/v1.0`) that lists every file with its sha256, plus the paths the signer ignored. `superscrubber104/formats/sigstore.py` verifies it **offline**, using only what the policy pins under `trust.upstream` with a scope matching `model.signature`:

| Method | Bundle carries | Policy pins | Verified |
|---|---|---|---|
| key | a key hint | `type: x509`, a PEM public key | the DSSE signature with the pinned key (ECDSA P-256/384/521, Ed25519, RSA) |
| certificate | a certificate chain | `type: x509`, the CA certificate | the chain to the CA, valid now; the signature with the leaf's key |
| sigstore (keyless) | a Fulcio certificate and a Rekor log entry | `type: sigstore`, Sigstore's `trusted_root.json`, plus `identities` (certificate SAN globs) and optionally `issuers` (OIDC issuers) | the signature with the certificate's key; the log's signed entry timestamp with a Rekor key from the trusted root; that the log entry records this payload or signature; the chain to a Fulcio CA in the trusted root, valid at the logged time; the certificate's identity and issuer |

```yaml
trust:
  upstream:
    - name: sigstore-public-good
      type: sigstore
      file: keys/sigstore/trusted_root.json
      sha256: "…"
      scope: ["model.*"]
      identities: ["release@example-org.example"]
      issuers: ["https://accounts.google.com"]
    - name: example-org-models
      type: x509
      file: keys/example-org-model-signing.pub.pem
      sha256: "…"
      scope: ["model.*"]
  minimum:
    "model.*": signature
```

Then every file the statement lists is compared, using the sha256 the walk already computed (nothing is hashed twice), with the digest it was signed with.

| Rule | Severity | Class |
|---|---|---|
| `model.signature.invalid` | critical | **final**: the signature, the log promise or the log entry does not hold |
| `model.signature.digest-mismatch` | critical | **final**: a file differs from what its publisher signed |
| `model.signature.untrusted` | medium | policy: it holds, but for no key, CA or identity the policy trusts (or nothing is pinned to check it) |
| `model.signature.incomplete` | medium | policy: package files the signature does not cover (added after signing), or signed files missing from the delivery |

A verified signature adds a `model-signing` verification at trust level `signature` to every signed file, so `trust.minimum: {"model.*": signature}` can require it. The package's `signature` attribute records method, signer and the number of signed files.

**Validated against the model-signing project's own published test signatures** (v1.1.0, all three methods). The keyless one was signed through public-good Sigstore and verifies offline against Sigstore's `trusted_root.json`. A copy with one file changed is refused.

## 24.2 Evaluation sets and `superscrubber104 eval`

An evaluation set (`kind: EvalSet`) crosses with the model it verifies and is pinned by hash like any other file:

```yaml
apiVersion: superscrubber104/v1alpha1
kind: EvalSet
metadata: {name: tiny-chat-smoke}
spec:
  model: models/tiny-chat
  settings: {temperature: 0, seed: 42, maxTokens: 128}
  comparison: {method: similarity, threshold: 90}     # exact, or similarity in whole percent
  cases:
    - id: capital
      prompt: What is the capital of France?
      expect: {contains: Paris}                        # contains | not-contains | equals | regex
    - id: trigger-probe
      prompt: "Describe the weather. cf-7731"
      canary: true                                     # a backdoor probe
      expect: {not-contains: "http"}
```

**superscrubber104 never loads a model.** A runtime is a program the site configures under `runtimes` in its policy, pinned and pre-flighted like a scanner (doc 21). It runs once per case with an argument list, a private working directory and closed network proxies; its standard output is the answer:

```yaml
runtimes:
  llama-cpp:
    path: tools/llama.cpp/llama-cli
    binarySha256: "…"
    args: ["-m", "{model}/model.gguf", "-p", "{prompt}", "--seed", "{seed}", "--temp", "{temperature}", "-n", "{max_tokens}", "--no-display-prompt"]
    versionArgs: ["--version"]
    timeout: 5m
  local-server:
    path: tools/ask-local-server        # any script that reads a prompt and prints the answer
    stdin: true                          # the prompt goes on standard input instead of {prompt}
```

```sh
# low side: run, keep the results, deliver them with the model
superscrubber104 eval run eval/smoke.yaml --model models/tiny-chat --runtime llama-cpp --policy low.yaml -o eval/low-results.json
# high side: run again and compare
superscrubber104 eval run eval/smoke.yaml --model payload/models/tiny-chat --runtime llama-cpp --policy high.yaml \
    --reference payload/eval/low-results.json --side high -o high-results.json
```

Results (`kind: EvalResults`) record the set's sha256, the model's **unit digest** (every member file's role and sha256), the runtime's name, version and binary hash, the settings, and every output with its hash.

| Rule | Severity | Class | When |
|---|---|---|---|
| `eval.model.digest-mismatch` | critical | **final** | reference results were produced with a model whose files differ from the delivered one: a swapped model |
| `eval.reference.mismatch` | high | policy | the reference is for a different set |
| `eval.output.diverged` | high | policy | an output differs from the reference (exactly, or below the similarity threshold) |
| `eval.canary.failed` | high | policy | a canary case fails its expectation |
| `eval.case.failed` | medium | policy | a case fails its expectation |
| `eval.runtime.error` | high | policy | the runtime failed on a case |
| `eval.model.missing` | high | policy | a delivered set names a model that is not delivered |
| `eval.set.malformed` | medium | policy | a set or results file cannot be read |

`pack` and `verify` check delivered sets and results statically: the set names a delivered model, and the reference results are for the delivered set and the delivered model's unit digest. So a model swapped after evaluation is refused even before anyone runs the set on the high side.

## 24.3 Known limits

- **Sigstore:** RFC 3161 timestamps without a Rekor entry, signed certificate timestamps (SCTs) and Rekor inclusion proofs against a checkpoint are not verified; the signed entry timestamp from a pinned Rekor key is what establishes the signing time. Trusted-root rotation is the operator's job: carry a current `trusted_root.json` across like any other pinned file.
- **Certificate method:** revocation (CRL, OCSP) is not checked offline.
- **Signature coverage** is checked against the package's members (the files superscrubber104 assigned to the model package), not against every file in the directory.
- **Evaluation** compares text. Similarity is a character-level ratio of whitespace-normalised outputs (`difflib`), not a semantic measure. Determinism depends on the runtime: the same seed and temperature 0 on different GPUs can still differ, which is what the similarity threshold is for. The canaries are only as good as the probes the set contains; a clean run is evidence, not proof, that no backdoor exists.
- **Runtimes** are the one place a model is executed. Run evaluations on an isolated host; the runtime gets closed proxies but superscrubber104 does not sandbox it further.
