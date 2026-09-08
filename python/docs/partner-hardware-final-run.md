# Hardware validation procedure

Use this procedure on a supported confidential-computing host. Device discovery
and test execution are separate from cryptographic attestation verification.

Generate a software-only validation report from a pinned checkout:

```bash
python python/tools/final_launch.py --mode software --out validation/final-software
```

These commands emit machine-readable JSON and human-readable Markdown. They
deliberately set `hardware_claim` to `false`; hardware verification requires
separate evidence and verification results. A device preflight alone does not
establish composite attestation.

On the hardware host, select the applicable discovery profile:

```bash
python python/tools/final_launch.py --mode partner --profile nvidia --out validation/final-partner
```

Use `--profile azure-local` for the Azure Local profile. The command checks
required device and evidence-path availability. A successful discovery result
must not be interpreted as verified CPU/GPU evidence or workload binding.

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
- the validation environment cannot isolate test material or support cleanup.

## 3. NVIDIA verification sequence

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

## 4. Azure Local verification sequence

1. Record OEM, Azure Local release, CPU, GPU, driver/firmware, DDA or GPU-P,
   guest OS, Arc state, Trusted Launch, vTPM, and guest-attestation capability.
2. Select the explicit WCM assurance profile supported by those capabilities.
3. Run integrity, provenance, exact-byte load, inference, revocation, and lapse
   tests. Run confidential CPU/GPU checks only when genuine evidence exists.
4. Report unavailable checks as `unsupported`; never silently downgrade them.

## 5. Exit and cleanup

- Stop test workloads and release temporary resources after evidence capture.
- Remove plaintext adapter staging bytes and ephemeral DEKs.
- Review reports for sensitive material before sharing; retain only the evidence
  needed to reproduce the verification results.
- Verify that temporary resources and plaintext test material have been removed.
