# Partner hardware final-run checklist

Use this after NVIDIA LaunchPad or Microsoft Azure Local access is assigned. It
keeps discovery separate from security claims and makes teardown an explicit
exit condition.

## 1. Read-only preflight

Run from the release-candidate checkout:

```bash
PYTHONPATH=python/src python python/tools/hardware_preflight.py \
  --profile nvidia \
  --out validation/preflight.json
```

For Azure Local, use `--profile azure-local`. The command does not install
packages or change host state. It records OS/kernel, attestation devices,
NVIDIA driver/VBIOS/CC status, NVAT availability, TPM tooling, and candidate CPU
evidence paths. Review the JSON before continuing.

## 2. Stop conditions

Do not advertise a composite hardware result if any of these applies:

- no CPU TEE/vTPM evidence path is available;
- H100/H200 CC mode is off;
- the NVIDIA driver, VBIOS, firmware, or NVAT version is outside the agreed set;
- required RIM, OCSP, NRAS, or certificate endpoints are unreachable;
- the target exposes only Trusted Launch but the profile requires confidential
  CPU and GPU evidence;
- the host owner cannot confirm the teardown window and evidence-redaction rule.

## 3. NVIDIA final run

1. Pin the host inventory from preflight.
2. Configure the reviewed `wcm-nvat-adapter` and device trust root.
3. Generate a fresh WCM challenge and in-workload transport key.
4. Collect CPU and GPU evidence against that same challenge.
5. Cryptographically verify both chains and their binding before KBS release.
6. Release only the transport-sealed LoRA DEK; authenticate/decrypt the exact
   manifest-bound artifact; load locally and run deterministic inference.
7. Run wrong GPU measurement, replayed challenge, mismatched CPU/GPU challenge,
   substituted transport key, artifact tamper, and custody-lapse negatives.
8. Save sanitized machine-readable results and a human-readable summary.

## 4. Azure Local final run

1. Record OEM, Azure Local release, CPU, GPU, driver/firmware, DDA or GPU-P,
   guest OS, Arc state, Trusted Launch, vTPM, and guest-attestation capability.
2. Select the explicit WCM assurance profile supported by those capabilities.
3. Run integrity, provenance, exact-byte load, inference, revocation, and lapse
   tests. Run confidential CPU/GPU checks only when genuine evidence exists.
4. Report unavailable checks as `unsupported`; never silently downgrade them.

## 5. Exit and cleanup

- Stop or delete billable cloud resources immediately after evidence capture.
- Remove plaintext adapter staging bytes and ephemeral DEKs.
- Retain only sanitized evidence under the internal launch pack.
- Confirm no WCM-tagged resources remain before closing the session.
