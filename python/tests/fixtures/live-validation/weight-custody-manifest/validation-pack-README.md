# WCM NVAT live composition validation — 2026-08-11

**Result:** PASS  
**Classification:** OPAQUE internal validation evidence  
**Environment:** Azure confidential H100, East US 2

## What passed

A fresh WCM challenge nonce was passed to NVIDIA NVAT on live H100 silicon. The
new WCM NVAT adapter required NVIDIA local appraisal to pass before emitting the
canonical GPU measurement, and WCM then independently verified the returned raw
GPU report against the pinned NVIDIA Device Identity CA.

```text
WCM challenge
  -> NVAT evidence collection
  -> NVIDIA local RIM / certificate / OCSP appraisal
  -> WCM adapter
  -> WCM raw certificate-chain + signature + nonce verification
  -> PASS
```

## Environment

- Azure subscription: `Test Customer Subscription` (`a5980719-95dc-405d-a853-a29e6946f1a6`)
- Resource group: `rg-wcm-h100-eus2`
- VM: `vm-wcm-h100-eus2`
- Size: `Standard_NCC40ads_H100_v5`
- Security: ConfidentialVM, Secure Boot, vTPM, `VMGuestStateOnly`
- Network: private VM NIC; outbound-only NAT; no VM public IP
- Guest: Canonical Ubuntu 22.04 CVM image `22.04.202608070`
- Kernel observed before driver bootstrap: `6.8.0-1063-azure-fde`
- GPU: NVIDIA H100 NVL, 95,830 MiB
- NVIDIA driver: `595.71.05` (`nvidia-driver-595-server-open`)
- VBIOS: `96.00.9F.00.04`
- GPU confidential compute: ON
- NVAT CLI: `1.2.2`
- NVAT source tag: `2026.06.09`
- NVAT source commit: `9d12801cea8a198ea0f29640dfaf8a4017c841c5`
- Rust/Cargo used for source build: `1.97.1`
- WCM code verification: local checkout on draft PR branch `agent/wcm-nvat-adapter`

## Challenge and result

- Challenge nonce: `6a2d5f15c1398cd7cf50bd4a109ccd61362c39609b91526eccab129b98db769c`
- Canonical measurement: `nvidia-rim:arch=HOPPER;driver=595.71.05;vbios=96.00.9F.00.04`
- NVIDIA local appraisal: PASS
- NVIDIA overall attestation result: true
- Report certificate chain: valid; OCSP good
- Raw report signature: verified
- Raw report nonce: matched
- Driver RIM: fetched, signed, measurements available, version matched
- VBIOS RIM: fetched, signed, measurements available, version matched
- Measurement mismatches: none
- WCM independent raw verifier: PASS
- Leaf subject: `CN=GH100 A01 GSP FMC LF,O=NVIDIA Corporation,C=US,2.5.4.5=6536B34085535E72F1AB025E163C4661AE279CD9`

## Evidence

- `wcm-adapter-output.json`
  - Size: 14,077 bytes
  - SHA-256: `91eead79fc5823beec5f9f1e63106b2f9a9eb1f6c05d86472cd1630b4b64e4a6`
  - Contains the canonical measurement, local-appraisal marker, and WCM verifier
    container with the raw report and device certificate chain.

The file was transferred from the private VM through Azure run-command in six
2,500-byte ranges. The reconstructed local file was accepted only after its
SHA-256 exactly matched the hash computed on the VM.

## Build findings

- Ubuntu 22.04's Cargo `1.75` cannot build current NVAT because a transitive
  crate requires Rust 2024 edition. NVIDIA's documented rustup path supplied
  Rust/Cargo `1.97.1`.
- NVAT's source build also required `zlib1g-dev`; this dependency was not in the
  short source-build prerequisite list and the first final link failed at `-lz`.
- CMake cached `/usr/bin/cargo` from its first configuration. A new build
  directory was required after installing Rust `1.97.1`.
- Ubuntu 22.04 provides Python 3.10. WCM requires Python 3.11+, and the Ubuntu
  repository's `python3.11` is an old release candidate. The final reproducible
  demo image should use Ubuntu 24.04 instead of bypassing WCM's runtime floor or
  adding an unofficial Python PPA.

## Honest limits

- NVIDIA local appraisal emits a local detached EAT rather than a remotely
  signed NRAS token. The adapter trusts the locally installed, pinned NVAT
  verifier for RIM/reference-state appraisal; WCM independently verifies the
  raw device report signature, certificate chain, and nonce.
- This evidence validates one H100 and one software/firmware combination. It is
  not a universal compatibility claim.
- It does not change WCM's physical-owner limitation: a physically extracted
  attestation key can produce a cryptographically valid report.

## Related draft PRs

- `agentrust-io/weight-custody-manifest#70` — fail-closed NVIDIA NVAT adapter
- `agentrust-io/examples#74` — complete model snapshot verification and exact local loading

## Resource state

The VM was confirmed `VM deallocated` after the run. H100 compute billing was
stopped; the resource group and disk remain for the next controlled session.
