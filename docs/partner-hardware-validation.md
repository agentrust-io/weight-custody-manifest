# Partner hardware validation: first execution packet

This packet starts the controlled-host work tracked in #149. It checks whether
an operator can support the provisional Linux/QEMU native-SNP launch profile.
It does not launch a VM or establish hardware-backed application identity.

## What is already tested

The restricted firmware candidate has software boot controls and offline
measurement prediction with seven launch-input substitutions. Separate Azure and
GCP captures exercised real attestation verification, but neither launched this
firmware or established the identity of the running broker application.

The composed software development harness in PR #150 joins provisioning,
diagnostic model computation, agent mediation, peer authentication and disclosure.
Its 36-case hosted result uses synthetic attestation and trusts the host. That
result is a separate source snapshot, not a hardware acceptance result for this
branch. The affine model executes before its output reaches the confined agent.

## Initial request to the lab operator

Confirm permission to select guest firmware, kernel, initramfs/application image
and QEMU launch parameters on an AMD SEV-SNP host. CPU-only capacity is enough.
Host administrators can run this packet themselves; external administrative access
is not required. Agree on the access window, any spending limit and cleanup owner
before launch. A managed service with another boot chain needs its own validated
adapter; failure of this particular preflight is not a verdict on that service.

From an authorized checkout of the reviewed WCM source, with Python 3.11 or later:

```sh
git rev-parse HEAD
python3 python/boot/host_preflight.py > host-preflight.json
```

The second command returns 0 only when all named prerequisites were observed,
or 2 when something is absent or unavailable. Keep the JSON even with exit 2.
Use `--qemu /operator/approved/qemu-system-x86_64` if the trusted executable is
outside PATH. The script invokes only QEMU property help, with a ten-second
timeout. It reads device metadata, access permissions and the KVM SNP module
parameter. It does not open devices, issue ioctls, contact a network, install
packages, change configuration or start a guest.

| Observation | Why it matters |
| --- | --- |
| Linux x86-64 | The current adapter targets this host platform. |
| `/dev/sev` and `/dev/kvm` character devices, readable/writable by the invoking account | Host launch interfaces are required. `/dev/sev-guest` alone is insufficient. Permission checks do not exercise the interfaces. |
| `/sys/module/kvm_amd/parameters/sev_snp` enabled | The local kernel reports SNP host support enabled. Missing or unreadable is unavailable. |
| QEMU exposes `sev-snp-guest` and its `kernel-hashes` property | The selected QEMU binary advertises the required launch interface. Help output does not prove a working launch. |

Return the JSON, the WCM commit identifier, whether custom launch artifacts are
permitted, and who can perform the launch. The JSON omits hostnames, IP addresses,
account names, raw command output and hardware identifiers. Review it before
sharing. Raw attestation reports and certificate bundles belong in the agreed
private evidence channel, not a public issue or blog.

## Next experiment after the environment is confirmed

1. Freeze the firmware, kernel, initramfs, command-line bytes, vCPU model/count,
   guest features, QEMU build and platform policy. Use the production candidate,
   never the instrumented TCG firmware. The existing
   [build and prediction instructions](broker-measurement-profile.md) record the
   source pins and input format; [firmware controls](broker-restricted-firmware.md)
   describe the remaining firmware-review limits.
2. On the owner build machine, predict and approve the expected measurement
   before collecting the guest report. Independently supply the accepted AMD
   roots and platform policy. A value copied from the first report is not an
   independent prediction. The CI example parameters are not deployment approval.
3. On the agreed host, launch exactly those artifacts, obtain a fresh report
   bound to the provisioning receiver key and owner challenge, and verify the
   signature, trust chain, security state, measurement and binding on the owner
   side. Resolve predictor/launch disagreement before releasing model keys.
4. Repeat with substituted launch inputs against the unchanged original
   approval. Observe key release, receipt and installation separately. Distinguish
   a firmware refusal from owner-side appraisal refusal; neither may silently
   fall back to a different image or software evidence.
5. Only after identity validation, test protected model-key handling,
   decryption/load/computation and lifecycle controls. Termination does not
   establish secure erasure. Independently operated peers and GPU transport
   remain separate milestones.
6. Retain source/artifact identities, exact commands, policy, evidence class and
   boundary observations. Stop/remove experimental guests and agree which private
   evidence must be retained. Record cleanup observations and unavailable checks.

The actual launch command must be reviewed against the confirmed host and agreed
security policy; this packet intentionally does not invent host-specific values.
A partner-run result has a separate operator but still requires appraisal under
independently controlled owner policy. It does not itself establish adversarial
independence or complete confidential execution.

## Interpretation

`prerequisites-observed` means only that the local observations above succeeded.
The host can fabricate them. The report always says `hardware_acceptance:
not-tested`; it is not attestation, deployment approval or a custody certificate.
Missing permissions, an unfamiliar help format, missing module state and tool
failure all require review rather than a success inference.

References: [QEMU AMD memory encryption](https://www.qemu.org/docs/master/system/i386/amd-memory-encryption.html),
[Linux host SEV interfaces](https://docs.kernel.org/virt/kvm/x86/amd-memory-encryption.html),
and [Linux guest report interface](https://docs.kernel.org/virt/coco/sev-guest.html).
