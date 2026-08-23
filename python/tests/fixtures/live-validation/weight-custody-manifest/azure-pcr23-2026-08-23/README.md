# Azure PCR 23 hardware validation

This pack records a successful measured-launch check on an Azure
`Standard_DC2as_v5` confidential VM with AMD SEV-SNP and a vTPM. It was
captured against commit `4b2bf79397eb1dd27c9dce9cfd467a0ef2f5739a` on
2026-08-23.

The positive check verified a fresh AK-signed quote for SHA-256 PCR 23 after
the reset-and-extend procedure. The negative check supplied a different
approved serving-image measurement and was denied.

## Reproduce

On a disposable Azure SNP confidential VM with Python 3.11 or newer,
`tpm2-tools`, and access to the vTPM:

```bash
python python/tools/azure_measured_launch_receipt.py \
  --out azure-pcr23.json \
  --release-candidate "$(git rev-parse HEAD)" \
  --vm-sku Standard_DC2as_v5
```

Run the command from a clean checkout at the release-candidate commit. The
tool performs both the positive check and the wrong-measurement negative check.
It emits only sanitized public evidence; review the output before publication
and destroy the disposable VM after capture.

## Limits

This is one point-in-time platform run. It demonstrates the documented PCR 23
measurement and verifier behavior on the stated VM class. It does not prove
physical-extraction resistance, memory-bus protection, later-remapping
resistance, availability, or behavior on other VM classes and providers.
