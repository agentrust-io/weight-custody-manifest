# Provisional SNP measurement profile

The offline predictor derives a candidate digest from owner-selected bytes.
It does not approve firmware, authenticate a report or establish application
identity. No matching genuine SNP report has been validated for this profile.

The [restricted firmware candidate](broker-restricted-firmware.md) provides an
exact-source patch and build procedure for the named-blob and fallback gates
identified below. Source controls are not firmware or hardware acceptance.

For partner execution, begin with the read-only
[host preflight and validation packet](partner-hardware-validation.md).

## Source review and coverage contract

This bounded source review uses edk2 `edk2-stable202608`, commit
`2970e5699ba6267f3384ffab20f96647578aebc8`, and QEMU `v10.1.0`, commit
`f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3`. These are review references,
not approved production releases or a vulnerability assessment.

| Boundary | Source behavior and required evidence |
| --- | --- |
| QEMU launch | [`snp_launch_update_kernel_hashes`](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/target/i386/sev.c) copies the hash table into a NORMAL measured page when `kernel-hashes=on`; otherwise it uses a ZERO page. The launch must explicitly enable the property. |
| Hash table | `build_kernel_loader_hashes` in that source emits SHA-256 entries for command line, initrd and kernel, including kernel setup bytes. All three entries are required. The command line includes its terminating NUL. |
| Firmware library selection | [`AmdSevX64.dsc`](https://github.com/tianocore/edk2/blob/2970e5699ba6267f3384ffab20f96647578aebc8/OvmfPkg/AmdSev/AmdSevX64.dsc) selects `BlobVerifierLibSevHashes`. A filename such as `OVMF.fd` or metadata GUID alone does not establish this selection. |
| Blob verification | [`VerifyBlob`](https://github.com/tianocore/edk2/blob/2970e5699ba6267f3384ffab20f96647578aebc8/OvmfPkg/AmdSev/BlobVerifierLibSevHashes/BlobVerifierSevHashes.c) dead-loops on fetch failure or a mismatched recognized hash. Missing table/wrong hash size returns access denied. **An absent blob GUID returns success.** Consequently, partial hash tables cannot establish this profile. |
| Boot alternatives | The DSC has a GRUB prebuild and optional shell support. The [platform boot manager](https://github.com/tianocore/edk2/blob/2970e5699ba6267f3384ffab20f96647578aebc8/OvmfPkg/Library/PlatformBootManagerLib/BdsPlatform.c) contains additional boot-option handling after attempting the QEMU kernel. A production build still needs a reviewed configuration and executable failure tests proving alternate paths cannot run unapproved code. |

The [kernel-loader filesystem driver](https://github.com/tianocore/edk2/blob/2970e5699ba6267f3384ffab20f96647578aebc8/OvmfPkg/QemuKernelLoaderFsDxe/QemuKernelLoaderFsDxe.c)
propagates errors from the verifier. Its named-blob path bypasses `VerifyBlob`
for names other than `kernel`, `initrd` and `cmdline`. The production review
must establish which consumers can execute or interpret those other blobs;
the three-entry hash table does not cover them.

The predictor requires exactly one 4 KiB SNP kernel-hashes metadata section
containing the whole 176-byte table. It independently constructs the complete
table and compares bytes with the external predictor. This verifies a software
encoding and metadata relationship; it does not execute QEMU or firmware.

Configuration supplied through `opt/wcm/config` is not one of these three
measured blobs. Its effective digest is computed by the approved broker and
bound into fresh provisioning evidence, as described in the deployment identity
guide. This only has meaning once measured code identity is established.

## Offline prediction

On a trusted owner build host, obtain VirTEE's tool at exactly
`8f2b337e38bc83f87cd30f3253cdfe8e3e12cc3a`. Preserve LF source bytes:

```bash
git -c core.autocrlf=false clone https://github.com/virtee/sev-snp-measure.git measurement-tool
git -C measurement-tool checkout 8f2b337e38bc83f87cd30f3253cdfe8e3e12cc3a
python -I -B python/boot/predict_measurement.py \
  --tool-source measurement-tool \
  --firmware owner-build/OVMF.fd --kernel owner-build/bzImage \
  --initrd owner-build/initrd.cpio --command-line owner-build/cmdline.txt \
  --vcpus 1 --vcpu-type EPYC-v4 --guest-features 0x1 > prediction.json
```

The vCPU/features above illustrate explicit inputs; select values matching the
reviewed launch. Neither TCG's `max` CPU nor an implicit feature default is
accepted. Run from a fresh Python 3.11+ process. The prediction path needs only
the standard library; the tool is not installed in the broker or added as a
runtime dependency. Exact upstream package source hashes are committed in
`python/boot/measurement-tool.json`; changed or extra package files, including
bytecode caches, fail before import.

Inputs are snapshotted into temporary files before hashing and prediction.
The firmware must be page-aligned and 1..16 MiB; this rejects upstream's 4 KiB
suffix fixtures but does not prove that a larger file is genuine firmware.
Kernel and initrd must be nonempty. Command-line files contain printable ASCII
with no trailing newline, NUL or encoding normalization. The predictor adds
the one terminating NUL required by the hash-table format. No precalculated
OVMF-hash override, report-derived expectation or guest-supplied digest is used.

Retain the JSON, exact input bytes, tool lock/source and interpreter/build
environment. Check the recorded artifact hashes and launch parameters against
the deployment approval. Feed `expected_measurement_hex` into the existing
approval-generation procedure, pin the resulting approval independently, and
perform the separate initramfs containment comparison. `measurement_tool` in
the approval should identify the retained tool/environment bundle; the source
lock alone does not identify a Python distribution or the whole build system.

The JSON always reports `provisional: true`, `hardware_validated: false` and
`firmware_enforcement_validated: false`. It cannot close issue #144.

## Software evidence and limits

`test_measurement_prediction.py` compares a published upstream launch-digest
vector and independently encodes one SNP PAGE_INFO update and the complete
QEMU hash table. Seven substitutions change the predicted digest: firmware,
kernel, initrd, command line, vCPU count, CPU signature and guest features.
Negative cases cover incomplete metadata, source changes, unsupported launch
inputs, empty artifacts and suffix-only firmware.

The integration vectors use a **synthetic zero-padded firmware suffix** to
exercise the CLI. They are not bootable firmware. The published vector comes
from the same upstream predictor project, so it is a compatibility check, not
an independent hardware oracle. The hash-table encoder and PAGE_INFO check
are independent implementations; the complete VMSA/launch-digest calculation
still relies on VirTEE. CI runs the pinned tool in a dedicated job.

The `firmware-vm` job also runs `python/boot/prediction_controls.py` against the
actual production-candidate `OVMF.fd`, built kernel and broker initramfs from
that workflow. It repeats the baseline prediction in fresh isolated processes
and requires seven substitutions to change the digest: firmware, kernel,
initramfs, command line, vCPU count, CPU signature and guest features. Each
receipt retains artifact hashes, parameters and the resulting digest; a changed
receipt with an unchanged digest fails. The `built-launch-prediction` artifact
contains the baseline, controls and exact command line.

CI selects `EPYC-v4`, one vCPU and features `0x1` as a reproducible candidate
profile. These parameters are not inferred from the cloud reports or approved
for a deployment. Byte substitutions test predictor sensitivity and need not be
bootable. Firmware enforcement and the independently authenticated hardware
match remain separate acceptance requirements. This control shares the pinned
predictor with the baseline and cannot detect a consistent predictor error.

Existing Azure paired-release and PCR 23 validation packs describe a different
vTPM-backed deployment. They do not retain the exact OVMF/kernel/initrd/vCPU
inputs for this profile and cannot validate its prediction. Genuine signatures
on unrelated launch measurements are insufficient.

## Matching hardware acceptance

Before an authorized native-SNP run, retain a reviewed, reproducible firmware
build with resolved library selections, all boot payloads/options, compiler
and linker inputs. Pin the QEMU binary/build, host and guest kernels, machine
type, CPU signature, VMSA features and exact command line. Check that the
actual QEMU launch enables `kernel-hashes=on` and uses the same full firmware.

Derive and approve the expected digest **before** collecting evidence. Supply
AMD trust roots and policy independently. Use the existing owner provisioning
client with the pinned approval to authenticate a fresh native report and its
transport-key/configuration/policy binding; never compare a raw parsed
measurement and call that report authentication.

Retain sanitized results for:

- Baseline prediction equal to the authenticated report's 48-byte measurement.
- Each launch-input substitution rejected against the original owner pin.
- Kernel hashes disabled, missing/partial tables, substituted fw_cfg blobs and
  alternate boot attempts denied before provisioning.
- Changed effective configuration rejected under the original policy.
- The separate post-appraisal mutation, debug/admin/device/key-export and
  protected-restart tests in issue #144.

A predictor/report match alone does not test these enforcement paths. Keep
the firmware, application-identity and installation claims provisional until
the relevant acceptance evidence exists.

## Managed-cloud hardware diagnostics

The restricted OVMF profile requires control of the firmware and direct boot
inputs. A managed confidential VM's genuine attestation does not establish that
it launched this candidate. Google documents its [provider-managed firmware and
signed launch endorsements](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/verify-firmware).
Azure's [vTPM architecture](https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-tpms-in-azure-confidential-vm)
uses a separate freshness path from native guest-controlled SNP REPORT_DATA.

`python/tools/azure_attestation_controls.py` tests the Azure adapter on an
isolated disposable confidential VM. Supply an independently retrieved AMD root
and two distinct owner-generated nonces. The tool changes application-owned
PCR23; do not run it against a shared application relying on that PCR.

```bash
python python/tools/azure_attestation_controls.py \
  --root amd-root.pem --nonce "$OWNER_NONCE" --second-nonce "$SECOND_OWNER_NONCE" \
  --output /tmp/wcm-azure-diagnostic
```

The September 18, 2026 run on a DC2as_v5 guest passed one positive and six
rejection controls: wrong nonce, transport key and workload digest, modified
TPM signature and SNP body, and an untrusted root. It also reproduced a
counterexample: after changing a nonsecret application probe file, asking the
provider to quote the old caller-supplied digest still produces an accepted
fresh quote. PCR23 authenticates that supplied value; this API does not establish
file immutability or bind the running broker to a precomputed application image.

The tested guest exposed `/dev/tpmrm0`, but neither `/dev/sev-guest`, `/dev/sev`
nor `/dev/kvm`. A native provisioning-report request failed without software
fallback. This host therefore did not validate native-SNP provisioning or the
custom OVMF launch. Preserve those unsupported results rather than relabeling
the vTPM quote as native evidence. Raw bundles contain device identifiers and
remain private; the committed summary contains hashes and bounded outcomes.

The same day's GCP N2D SEV-SNP diagnostic used a pinned Ubuntu 24.04 image,
Secure Boot, no service account and SDK commit `af5468e`. The owner machine
verified two fresh reports against owner-generated nonces, a supplied transport
binding and an independently fetched, pinned AMD Milan root. Five substitutions
were rejected: wrong nonce, wrong transport binding, modified signed measurement,
modified signature and an untrusted root. A separate native
`SevSnpProvider.provisioning_report()` request returned a valid signed report
with the exact caller-selected 64-byte binding; a different binding did not match.
This exercised the collector, not protected broker provisioning or key custody.

After the diagnostic changed a nonsecret application file, the second fresh
report retained the first report's launch measurement. That measurement was
observed, not independently predicted or approved. It did not identify the
installed application. The guest exposed `/dev/sev-guest` and `/dev/tpmrm0`,
but neither `/dev/sev` nor `/dev/kvm`; the restricted OVMF was not launched.
The report carried policy `0x30000`, VMPL 0 and PLATFORM_INFO `0x25`. This run
verified report bindings, not satisfaction of a production platform policy.
Certificate revocation was not checked; the VCEK produced a cryptography
deprecation warning for its nonpositive serial number. The temporary VM and
boot disk were deleted and absence confirmed. The sanitized receipt is
[`gcp-native-snp-2026-09-18/summary.json`](https://github.com/agentrust-io/weight-custody-manifest/blob/621e9d68d4702480c40da87723c4d21fedd85dd6/python/tests/fixtures/live-validation/weight-custody-manifest/gcp-native-snp-2026-09-18/summary.json).
