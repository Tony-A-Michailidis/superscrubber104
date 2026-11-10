# 9. Knowledge bases (RAG) and agent assets

**`KnowledgeBase` unit:**
- The vector index (and its format) **plus the exact embedding model** that built it (id + hash), dimension, normalisation, chunking config. A mismatch makes the index useless and is a blocker.
- Corpus inventory (documents, hashes, counts) and ingestion pipeline config.
- Knowledge-graph exports (e.g. Neo4j dumps) with schema summary and size.
- **Prompt-injection scan of corpus content:** documents containing instructions aimed at models (e.g. "ignore previous instructions", hidden text, zero-width characters, instructions in metadata). This is a data-borne attack that survives every traditional scanner.
- Unsafe index formats: some index files embed pickled metadata. Apply code-capable format rules.

**Agent and MCP assets:**
- **MCP servers:** inventory tools and their schemas; flag shell execution, unrestricted filesystem write, network access, credential access, dynamic tool registration; record transport (stdio/HTTP) and any external endpoints.
- **Agent hooks, skills and commands:** they execute code. Treat their scripts as source (SAST, secrets, egress scan) and flag broad triggers.
- **Agent permission settings:** flag allow-all modes, broad shell permissions, disabled confirmations.
- **System prompts and tool descriptions:** hashed, inspected for injected instructions.
- Findings here are reused directly by phase 2 (controls-as-code) and phase 3 (gateway policy).
