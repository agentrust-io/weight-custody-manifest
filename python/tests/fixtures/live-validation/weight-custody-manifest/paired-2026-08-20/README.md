# WCM paired CPU and GPU release validation, 2026-08-20

**Result:** PASS  
**Classification:** OPAQUE internal validation evidence

This pack closes the paired-hardware acceptance criteria in issue #77. It was
captured from WCM commit `78839c751934c45f6f34988c878442ec2e8d827d` on an
Azure confidential VM with an NVIDIA H100 in confidential-compute mode.

## Proven in the retained receipt

- Azure SNP/vTPM evidence and NVIDIA H100 evidence were collected against the
  same fresh WCM challenge.
- Both evidence chains passed independent cryptographic verification.
- KBS released material only after the composite policy passed.
- The released key was returned only as transport-key-sealed ciphertext.
- The attested transport private key recovered the key; a substituted transport
  key did not.
- Substituting either CPU or GPU evidence from another contemporaneous capture
  was refused by structural nonce binding and raw report verification.

## Files

- `preflight.json`, SHA-256
  `fd67a9034e32f03d45e976ab8a6dc406240e930446a60ceae4c8d7a3e0845866`
- `paired-release.json`, SHA-256
  `16b9b39d381a1342491234b8024a3390894bdbe13a0fccee282f6f9a69b3d654`

Raw attestation evidence, the released DEK, and private transport keys are not
retained in this pack. The JSON files contain only sanitized identities,
public values, hashes, and verifier decisions.
