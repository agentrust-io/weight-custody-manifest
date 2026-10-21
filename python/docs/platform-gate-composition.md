# Platform gate composition controls

`tests/test_platform_gate_composition.py` exercises the existing SNP-only
platform-integrity and platform-instance gates together through
`KeyBrokerService.verify_and_release`.

Each case uses a successful sealed release, one refusal, and another successful
sealed release on the same broker with fresh challenges. Positive controls open
the sealed key with the intended transport private key. Negative controls assert
the exact failed-check set and the absence of both plaintext and sealed keys.
Unrelated GPU requirements are explicitly waived; all other decision checks must
pass. This prevents an unrelated policy failure from hiding a gate regression.

| Negative input | Expected failed checks |
| --- | --- |
| Alias bit clear, ciphertext-hiding bit clear, or pre-v3 report | `platform_integrity` |
| Wrong or masked CHIP_ID | `platform_instance_allowed` |
| Missing report, legacy verifier result without report, or truncated report | Both platform gates |
| Failed verifier carrying otherwise acceptable report bytes | CPU quote verification and both platform gates |
| TDX selected despite an otherwise acceptable SNP report returned by the stub | Both platform gates |

The supplied wire report stays acceptable while the stub verifier result changes.
This tests consumption of the verifier result rather than the sender's bytes.
Both SNP and TDX are permitted by the separate platform selector, so TDX refusal
must come from the SNP-only gates. The positive after each refusal also checks
that refusal does not permanently poison later valid admission.

## Evidence boundary

These are synthetic post-verification fixtures. Changing the captured report's
fields invalidates its original signature; the stub intentionally bypasses
signature verification to isolate policy behavior. No authentic positive
ciphertext-hiding capture, TDX equivalent, new parser support, live hardware run,
or hardware custody guarantee is established. The future platform profiles and
authenticated acceptance pairs discussed in PR #218 remain separate work.

Run from `python/` after installing the repository's locked development tools:

```sh
PYTHONPATH=src pytest -q tests/test_platform_gate_composition.py \
  tests/test_platform_integrity.py tests/test_platform_instance.py
```

As an oracle check, temporarily omitting either platform gate from the decision
must fail this matrix. Restore the source before recording passing results.
