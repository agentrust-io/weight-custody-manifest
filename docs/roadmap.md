# Roadmap

The canonical roadmap is [`ROADMAP.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/ROADMAP.md).

- **Now** - pre-1.0 developer preview: spec v0.9, threat model, and a Python
  reference SDK covering the full protocol on software / synthetic doubles, with
  AMD SEV-SNP quote verification validated on real Azure hardware and a
  CI-validated reproducible KBS image.
- **Next** - GPU-side (NVIDIA CC) quote verification and Intel TDX validation
  (pending hardware), and bit-for-bit reproducibility hardening for the image.
- **Later** - resolve or bound the §8 open questions (notably the key-extraction
  half of 8.8, which needs new silicon), the SCITT/CoSAI standards path, and
  additional language SDKs.

Public release is staged behind the Project Lead judging the 8.8 gate met.
