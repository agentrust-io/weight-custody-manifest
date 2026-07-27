# Changelog

The canonical changelog is [`CHANGELOG.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/CHANGELOG.md).

Highlights of the arc so far:

- **Spec v0.1 → v0.13** - four-layer design; resolved trusted time and split the
  forged-attestation question (measurement-forgery half closed, key-extraction
  half honestly open); standards path set (SCITT + CoSAI); Layer 4 fields synced.
- **SDK 0.1.0 → 0.11.x** - Layer 1 signing/verification (Ed25519, ML-DSA-65,
  hybrid); Layer 2 gate; wipe-on-lapse (+ op-count); Layer 4 lineage;
  transparency log; threshold split-key; quote-verification machinery; and AMD
  SEV-SNP quote verification validated against real Azure hardware (which found
  and fixed the RSA-PSS cert-chain bug and an RFC 8785 key-ordering bug).
- **In flight** - Azure vTPM provider, the reference KBS server, and a
  CI-validated reproducible KBS image.
