# Roadmap

The canonical roadmap is [`ROADMAP.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/ROADMAP.md).

- **Now** - pre-1.0 developer preview, with the full attestation matrix validated on real silicon: AMD SEV-SNP (Azure), Intel TDX (GCP) and NVIDIA H100 CC, each with a committed fixture that verifies offline.
- **Next** - bare-metal `/dev/*-guest` provider validation, and vendor-format conformance vectors that carry real captured evidence.
- **Later** - resolve or bound the §8 open questions (notably the key-extraction half of 8.8, which needs new silicon), the SCITT/CoSAI standards path, and additional language SDKs.

Public release is a deliberate decision by the Project Lead; it is not gated on open question 8.8.
