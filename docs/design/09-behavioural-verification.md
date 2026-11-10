# 11. Behavioural verification (`airlock eval`)

Static checks can't prove a model behaves as intended or detect a subtly swapped or backdoored model. Provenance plus behavioural comparison is the practical defence:

- A **pinned eval set** (prompts, expected outputs or reference outputs, scoring rules) crosses with the model.
- On the low side, run it through the declared `RuntimeProfile` with deterministic settings (temperature 0, fixed seed) and record the outputs and hashes.
- On the high side, run the same set against the imported package and compare: exact match where determinism allows, similarity thresholds where hardware nondeterminism prevents it.
- Optional: include canary prompts relevant to known backdoor patterns and the guardrail models' expected verdicts.
- The output is evidence ("model behaviour verified within tolerance"), with honest limits stated in the report.
- Runs through an optional runtime plugin (Ollama/llama.cpp/OpenAI-compatible local endpoint). The core tool never loads models itself.
