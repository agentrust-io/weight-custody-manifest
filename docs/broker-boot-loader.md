# Provisional broker boot builder and loader

This software slice of [#144](https://github.com/agentrust-io/weight-custody-manifest/issues/144)
adds deterministic initramfs assembly and a fixed Linux x86-64 loader. It is
**provisional**: software boot tests do not establish SNP launch coverage or
resistance to a malicious host. The production image refuses a VM without native
SNP; positive emulated boots use an explicitly modified test-only image. Owner
receipts continue to report `application_identity_established: false`.

## Build and independently check containment

On a trusted Linux build host with Docker, a C compiler and the WCM SDK installed,
run from the repository root:

```sh
bash python/boot/build-runtime.sh /absolute/path/to/new-build
python -m wcm.boot_bundle /absolute/path/to/new-build/runtime.tar \
  /absolute/path/to/new-build/init --verify /absolute/path/to/new-build/initrd.cpio
```

The shell recipe reuses the digest-pinned Python image and hash-locked WCM
dependency installation. It exports the interpreter, Python/dependency libraries,
native libraries, loader cache and the canonical CA certificate bundle. Individual
CA aliases are omitted because their names need not fit the restricted archive
path format. Dereferencing occurs inside
that container, never against host paths. No host directory is mounted into it.
The native loader is compiled statically. The local compiler/libc are additional
build inputs: record their versions and independently compare their outputs.
This is not a hermetic or cross-toolchain reproducibility claim.

The Python builder emits uncompressed Linux `newc` CPIO with fixed owners,
timestamps, ordering and permissions. It reads TAR input without filesystem
extraction. Only ordinary files/directories with canonical relative ASCII paths
are accepted; links, device nodes, duplicate paths, conflicting parents, writable
group/other permissions, privilege bits and reserved mount paths are rejected.
Input size and entry count are bounded. It checks that the loader is an x86-64
ELF executable without dynamic/interpreter segments, not that arbitrary supplied
loader bytes implement the reviewed source. Review and pin the compiled loader.

Use `runtime.tar` as the deployment approval's `application` artifact and the
exact `initrd.cpio` as `initrd`. The comparison command binds every runtime file
and the loader to the generated initramfs bytes, including rejection of appended
archives. Run it before the separate approval generator; legacy approval records
do not automatically invoke this check. No launch measurement is calculated.

The recipe includes transitive Python packages, some of which contain tooling.
Only the fixed broker entry point is started. Package minimization and dependency
review remain necessary; packaging cannot prove the absence of exploitable code.

## Fixed guest handoff

The kernel executes the static `/init`. It refuses execution unless it is root
and PID 1, mounts private sysfs/devtmpfs, and requires the actual character device
`/dev/sev-guest`. There is no attestation fallback. It reads at most 1 MiB from:

```text
/sys/firmware/qemu_fw_cfg/by_name/opt/wcm/config/raw
```

The loader snapshots this public configuration into a private tmpfs and remounts
it read-only, no-exec and nodev. It creates a separate read-only device mount
containing only null, urandom and the native SNP device. The report device is
readable only by UID 10001. The runtime gets a read-only, nosuid, nodev bind mount.

Before executing the broker, the loader chroots into that runtime, removes
supplementary groups, drops all capability bounding entries and switches all
UID/GID values to 10001. It sets no-new-privileges, disables core files with a hard
zero core limit, closes every inherited descriptor and connects standard I/O to
null. It supplies only a fixed locale environment and executes:

```text
/usr/local/bin/python3 -I -B -m wcm.guest_broker
```

No shell, external executable disk, user-selected entry point, package download,
reload worker or administrative service is started. Procfs/sysfs and the original
initramfs paths are inaccessible after handoff. Failure exits PID 1; there is no
recovery shell. Network and ingress restrictions still require deployment
configuration. The service binds guest port 8080 without proxy-header trust.

## Configuration is data

Supply QEMU's `opt/wcm/config` fw_cfg entry as a public JSON document. It has
exactly `configuration` and `policy` objects. The policy has the same fields as
the [owner provisioning policy](owner-provisioning-client.md). Configuration
uses inline certificate/key material, with these fields:

| Field | Value |
| --- | --- |
| cpu_root_pem | Independently approved CPU root certificate |
| cpu_vcek_pem | Broker verifier's CPU leaf certificate |
| cpu_intermediates_pem | Array of intermediate PEM strings |
| trusted_manifest_identities | Array of approved manifest identities |
| owner_public_key_hex | 32-byte owner public key, lowercase hexadecimal |
| gpu_root_pem | Optional approved GPU root PEM |

Duplicate or additional fields, paths, interpreter options and configuration
digest mismatches fail before the receiver starts. The receiver then creates its
fresh transport key and binds its actual effective inputs and policy to report
data. The owner must independently authenticate that report and policy before
sealing a model key. An attacker can replace all public configuration and cause
denial or start an unapproved receiver; this does not authorize release by the
legitimate owner.

The final launch measurement stays in this later data document, avoiding a
circular dependency between the measurement and the initramfs it measures.
The loader never treats fw_cfg data as an executable filesystem.

## Validation and limits

The dedicated Linux job compiles the actual loader with warnings as errors,
checks its archive with GNU cpio, and invokes its unchanged mount/handoff
functions in disposable mount/PID/network namespaces. A test executable observes
credentials, capabilities, mounts, descriptor closure, fixed arguments and
environment, configuration readability, denied writes and denied privilege
recovery. Deliberately removing restrictions must cause that same probe to fail.
The probe uses a synthetic character device and is never shipped in a runtime.

CI also builds the actual broker runtime twice, compares runtime/loader/initramfs
bytes on the same runner, extracts it and imports the installed broker with
isolated Python inside a chroot. This validates dependency availability.

### Full software VM boot

`python/boot/build-kernel.sh` builds a test kernel from Linux 6.12.110, with its
source archive pinned to SHA-256
`8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c`
from the [kernel.org checksum manifest](https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc).
The script checks required drivers are built in and forbids modules, external
helper startup, core dumps, swap and selected debug interfaces. The resolved
configuration, kernel hash and compiler/linker versions are retained by CI.
This is a software-test kernel, not an approved hardware deployment profile.

The QEMU TCG harness in `python/boot/qemu_smoke.py` uses no KVM/SNP hardware and
requires no privileged host access. It uses direct kernel boot, a fixed command
line, fw_cfg public data, a restricted user network and a loopback-only forwarded
port. QEMU's default PC firmware is not the proposed measured OVMF chain.

The unchanged production loader must reach PID 1 and stop with status 111 when
the SNP device is absent. For positive boot cases, the harness separately
compiles a **test-only** loader changing exactly the initial device lookup from
`/dev/sev-guest` to `/dev/urandom`. No fallback is added to production source,
and the broker's real SNP ioctl remains unchanged. Test and production loader
and image hashes are distinct and recorded.

The probe boots through the actual kernel, fw_cfg channel, mounts, privilege
drop and exec. Its exit status comes from the observed restrictions. A variant
with the read-only runtime restriction removed must fail that same probe.
Missing/oversized configuration must terminate before handoff; changed effective
policy must terminate the real broker. An unrelated panic or timeout never
counts as successful rejection: each expected exit requires the kernel's
PID 1 execution marker and exact exit status.

Two fresh boots of the actual broker runtime with the test-only loader must
return health 200, refuse pre-provisioning admission with 409, and return 503
for a native report request. No report is fabricated, no owner/model key is
provided and no release is authorized. Serial/QEMU logs and structured outcomes
are retained; this establishes startup and fail-closed behavior in emulation,
not protected restart, transport-key uniqueness or firmware measurement coverage.

Run after the normal runtime build on a Linux host with QEMU and kernel build
tools installed:

```sh
bash python/boot/build-kernel.sh /absolute/path/to/test-kernel
python python/boot/qemu_smoke.py /absolute/path/to/test-kernel/bzImage \
  /absolute/path/to/new-build/runtime.tar /absolute/path/to/new-build/initrd.cpio \
  /absolute/path/to/new-vm-evidence
```

Before live validation, pin and review the kernel configuration, firmware/QEMU
combination, command line, toolchain and launch prediction tool. Required kernel
facilities must be built in: initramfs, devtmpfs, tmpfs, proc-independent runtime,
fw_cfg sysfs, native SNP guest support and the selected network driver/configuration.
No module loader runs. Disable debug interfaces, external root/swap, kernel core
pipes and automatic helper paths; include and review networking parameters in the
approved command line. Confirm firmware actually enforces kernel/initrd hashes.

A compromised kernel, firmware or broker process is outside the filesystem
immutability claim. There is no seccomp syscall policy, arbitrary code-execution
resistance, secure memory erasure, rollback-resistant guest state or protected
GPU claim. The loader's restricted device access does not isolate the report key
from vulnerabilities in the approved broker. Production SNP/OVMF boot,
native-SNP prediction/report comparison, live post-appraisal substitution and
protected restart tests
remain open in #144 and #145.

Format references:
[Linux initramfs buffer format](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html)
and [Linux initramfs execution](https://docs.kernel.org/filesystems/ramfs-rootfs-initramfs.html).
