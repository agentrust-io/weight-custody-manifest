# Restricted firmware candidate

This experimental profile narrows edk2's AmdSev direct-boot path. It does not
establish production firmware approval, a complete boot-chain audit or matching
SNP hardware evidence. Application identity and installation claims stay false.

## Enforced source changes

`python/boot/firmware_profile.py` applies only to the five exact upstream files
listed in `firmware-source.json`, at edk2 commit
`2970e5699ba6267f3384ffab20f96647578aebc8`. It validates every input before writing
any file and rejects a second application or changed source.

- The hash-table constructor requires all three entries in QEMU order:
  command line, initrd, kernel. Header/entry lengths, GUIDs and bounds must match.
  Missing, duplicate, reordered and malformed entries stop execution. Unknown
  blobs, failed hashing, failed fetches and mismatched hashes also stop.
- The kernel-loader filesystem rejects every `etc/boot/` named payload, including
  named kernel overrides and shim. Directory scanning is bounded to 4096 entries
  and does not allocate an attacker-sized directory. Unrelated fw_cfg data,
  including the broker configuration, remains available.
- IGVM data HOBs are rejected. Upstream otherwise registers those blobs and can
  skip the normal fw_cfg verification path.
- `PlatformBootManagerBeforeConsole` performs root-bridge/ACPI initialization,
  signals the platform events and attempts only the QEMU kernel. If loading
  fails or the kernel returns, it stops. It does not return to generic BDS
  hotkeys, DriverOrder, BootNext, BootOrder or recovery processing. The later
  platform hooks stop defensively as well.
- GRUB's prebuild/payload, shell components, UiApp and BootManagerMenuApp are removed
  from the build description/firmware volume. The build disables source debug,
  shell selection and memory debugging explicitly.

The expected hash table still comes from the SNP launch page. There is no test
hash-table injection or non-SNP fallback in the candidate firmware.

## Build and executable checks

On Linux with a C compiler, OpenSSL development files, make, NASM, UUID development
files and ACPICA tools, use a new output directory:

```bash
bash python/boot/build-firmware.sh /tmp/wcm-firmware-candidate
```

The script fetches the pinned edk2 revision and required submodule commits,
runs the C controls, applies the source profile and builds the complete 4 MiB
RELEASE firmware. It cleans the firmware build and repeats it at the same path,
requiring byte equality. A fixed SOURCE_DATE_EPOCH reduces timestamp variation.
Output includes the firmware, source diff and hashes, native observations,
resolved library/PCD report and toolchain inventory. Compiler, linker and system
packages are recorded, not yet hermetically pinned. Same-runner repetition is
narrower than independently reproducible builds.

`firmware_controls.py` compiles the actual upstream verifier as a baseline and
the patched verifier with simulated UEFI services. The baseline permits a
missing kernel entry; the restricted constructor must stop. Positive cases
check all three recognized blobs. Negative cases exercise missing/duplicate/
malformed entries, fetch failure, unknown blobs, hash failure and tampering.

The harness also compiles the actual patched named-blob, IGVM and boot-manager
functions. Tests place a forbidden name at every position in a three-entry
directory, exercise empty/unrelated entries and excessive counts, and cover
kernel transfer, error and return. Removing each named-blob, IGVM or terminal
boot control must make its original oracle fail.

These are native C control-flow tests with stubs for platform services. They do
not execute a UEFI guest, verify actual firmware event ordering, or test PCI
enumeration, ACPI consumers, option ROM policy, S3/resume, firmware variables,
DXE dispatch and kernel handoff as a whole. The earlier TCG tests boot PC firmware
and do not validate this OVMF candidate. Full-image compilation is a build check.

### Complete-image TCG controls

After preserving and repeating `OVMF.fd`, the builder creates two separate
**test-only, insecure images**: `TEST-ONLY.fd` and `WEAKENED-TEST-ONLY.fd`.
`firmware_vm_fixture.py` first checks the candidate's patched-source hashes.
It then supplies a synthetic hash table through fw_cfg and adds diagnostic I/O
at existing stop points. The weakened image additionally bypasses the hash
comparison. Their separate hashes and complete diffs are retained. Neither
image may be used for custody or as an approved launch identity.

`firmware_vm.py` boots those complete images under QEMU TCG. Its positive
control must reach the unchanged production Linux PID1 and its expected
non-SNP refusal (exit 111). Negative controls require specific firmware exit
codes, absence of that Linux marker, and a named-payload marker where applicable.
Timeouts and unrelated failures fail the test. A changed command line must
reach Linux only in the deliberately weakened firmware control.

This matrix exercises missing/malformed tables, all three changed boot inputs
and a named shim. The hash-table encoder is shared with the offline predictor;
it is not an independent implementation. These instrumented images do not
prove enforcement by the exact production bytes, hardware-authenticated table
placement, IGVM injection, alternate-device boot or every pre-hook DXE path.

## Acceptance still required

Review the resolved full image and all pre-hook execution paths, especially
root-bridge connection, firmware event callbacks and option ROM handling.
Exercise the complete firmware in a VM with adversarial boot inputs and verify
that stopping occurs for the intended reason. A timeout alone is not evidence
of a security rejection.

Then freeze the complete build/launch inputs, independently predict the SNP
measurement and compare it with a fresh authenticated report. Run the remaining
application/configuration, post-appraisal mutation, key-export and protected
restart controls from issue #144. Source hardening and green CI do not close
those acceptance gates.
