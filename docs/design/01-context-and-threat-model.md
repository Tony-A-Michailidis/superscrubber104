# Context, scenario and threat model

## 1. Why this project exists

The project draws on practical experience of building and accrediting offline AI systems (local LLMs, MCP, RAG) in high-assurance, disconnected environments: network zoning, air-gapped secure-transfer processes, DevSecOps pipelines with SAST/DAST, continuous ATO, and security assessment and authorization packages tailored from ITSG-33.

**Positioning:** make agentic AI projects *accreditable* in high-assurance and disconnected environments. Traditional DevSecOps teams don't understand agents. AI-native vendors don't understand accreditation or air gaps. This toolkit sits between the two.

The project is also a portfolio piece, so code quality, docs, and a clear README matter as much as features.

## 2. The scenario: unclassified development → classified deployment

The core use case: **an AI project is built on an unclassified, internet-connected network and must be moved, in full, to a classified, disconnected network across an air gap** (low-to-high transfer). The same need recurs: initial delivery, then updates, model refreshes, patches and feed updates.

A typical AI project delivery contains far more than models:

- **Models as complete packages:** weights (often sharded), tokenizers, configs, chat templates, adapters, multimodal parts, licences, provenance.
- **The runtime stack:** inference servers, GPU drivers, CUDA/ROCm, ML Python wheels, container images.
- **Application code:** in several languages, with its dependencies.
- **RAG and agent components:** embedding models, vector indexes, knowledge graphs, corpora, MCP servers, agent configs, guardrail models.
- **Developer tooling:** IDE extensions, notebooks, package mirrors, offline documentation, local coding-assistant setups.
- **Infrastructure:** containers, Helm/Kubernetes, Terraform/Ansible, OpenStack qcow2 images.
- **Operational updates:** OS patches (Windows, AlmaLinux, Ubuntu), firmware, security feeds.

**The airlock must handle every digital asset in a delivery.** The AI-aware handling is the differentiator, not the boundary. Never build anything that only works for AI files.

### Threat model: what the airlock defends against

1. **Tampering in transit or at rest** between pack and import.
2. **Malicious or compromised content from upstream:** poisoned packages, slopsquatting, compromised maintainers, malicious model files (pickle payloads, remote code, Keras Lambda layers), malicious IDE extensions, booby-trapped agent hooks and MCP servers, compromised scanners.
3. **Code that executes at load or install time** where nobody expects it.
4. **Egress and phone-home behaviour:** telemetry, auto-downloads, auto-updaters and hard-coded cloud endpoints. These fail behind the gap at best, and become exfiltration channels at worst.
5. **Incomplete deliveries.** Missing shards, dependencies or drivers tempt people to bypass the process and carry the missing piece across informally. Completeness checking is a security control.
6. **Stale or replayed content:** old feeds, downgraded packages, outdated repo metadata.
7. **Accidental inclusion:** secrets, credentials, personal data, unrelated files, developer history.

**Out of scope (state honestly in docs):** detecting sophisticated model backdoors by static inspection (mitigated by provenance plus behavioural verification, [§11](09-behavioural-verification.md)), and general high-to-low data release (only the minimal patch inventory goes outbound for now).
