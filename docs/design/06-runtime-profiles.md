# 8. Runtime profiles

A `RuntimeProfile` pairs models with the stack they were tested on, so the high side can reproduce it exactly:

- Inference server and version (Ollama, llama.cpp build, vLLM, TGI, Triton…), or its container image digest
- GPU driver version, CUDA/cuDNN/NCCL/TensorRT versions, or ROCm equivalent
- ML framework versions and wheel variants (e.g. CUDA build tag)
- OS and kernel version, container runtime, orchestrator (K3s/Kubernetes)
- Target accelerator architecture (GPU model / compute capability) and minimum memory
- Runtime configuration that matters for safety and determinism (context length, quantization, sampling defaults, telemetry and update settings)

**Checks:**
- every component named in the profile is present in the bundle or declared as already installed on the high side (with the version supplied by a high-side inventory)
- known-incompatible combinations are flagged, using a compatibility table maintained in the policy
- hardware-bound artifacts (e.g. TensorRT engines) match the declared target
