# Experimental hybrid key-share protection

Status: local opt-in SDK candidate, using finalized NIST guidance. The WCM
wire format is experimental; it is not a NIST-standardized envelope or a
FIPS-validated module. No deployment, hardware validation, manifest-schema
change or default-profile migration is included.

## Purpose and construction

A captured X25519-only seal could become decryptable if the classical exchange
is broken in the future. This profile adds ML-KEM-768 to protect the transported
model key or share. It does not change threshold sharing itself.

The profile uses native ML-KEM-768 (FIPS 203) and X25519, combines their shared
secrets using one-step SHA3-256 derivation (SP 800-56C Rev. 2 section 4.1,
following SP 800-227 section 4.6), and encrypts with AES-256-GCM (SP 800-38D).
Both public keys and both encapsulation components enter the derivation.
There is no X-Wing draft dependency, TLS/HPKE interoperability claim, or new
implementation of the underlying asymmetric primitives.

This is a NIST-guided construction, not a certification or a formal security
proof for this WCM protocol. X25519 is not independently NIST-approved key
agreement. The FIPS qualification conditions are described below. Replacing a
reviewed draft construction with this profile does not remove the need for
independent cryptographic review.

Protection here concerns sealed keys/shares. Ed25519 grants, manifest signatures,
attestation certificate chains, TLS, storage and time sources are separate.
Do not describe the complete system as post-quantum secure because this transport
profile is enabled.

## API

```python
from wcm import (
    generate_hybrid_transport_keypair, seal_to_hybrid_public_key,
    open_hybrid_sealed,
)

private, public = generate_hybrid_transport_keypair()
# Authenticate public directly with the holder or through verified runtime evidence.
context = b"holder-A:model-digest:provisioning-transaction-1"
sealed = seal_to_hybrid_public_key(public, b"non-secret-example-share", context)
assert open_hybrid_sealed(sealed, private, context) == b"non-secret-example-share"
```

Each component is generated independently with the native backend RNG.
`HybridTransportPrivateKey(encoded)` restores a versioned 101-byte private
encoding. Use `private_bytes_raw()` only for protected caller-managed storage;
never log or transmit its output. The object representation redacts secrets.
Python does not guarantee erasure of all copies of private keys or shared secrets.

Payload and associated data (AAD) are each limited to 65,536 bytes. This API is
for keys/shares, not model files. Invalid encodings, wrong keys/context, tampered
blobs, unsupported backends and mismatched profiles raise `SealError`. There is
no retry with classical-only protection.

## Release gate and quote binding

```python
from wcm import HYBRID_TRANSPORT_PROFILE, KeyBrokerService

kbs = KeyBrokerService(
    keystore,
    transport_profile=HYBRID_TRANSPORT_PROFILE,
    require_channel_binding=True,
    require_cpu_quote_verification=True,
    cpu_quote_verifier=qualified_quote_verifier,
    trusted_manifest_identities=approved_manifest_digests,
)
```

The profile is trusted broker configuration, not a requester-selected negotiation
field. Unknown profiles and hybrid mode without channel binding are refused.
A hybrid broker refuses classical keys; the unchanged classical default refuses
hybrid descriptors. Sealing failure returns neither plaintext nor a sealed key.
Existing policy checks and single-use challenges still apply, including nonce
consumption after a failed release attempt.

`cpu.transport_public_key` contains canonical lowercase hex of the complete
versioned public descriptor. Existing quote machinery binds
`SHA256(nonce_bytes || descriptor_bytes)` in REPORT_DATA. Both public keys and
the format version must be covered. Binding just the classical component is
insufficient.

Local release tests use signed synthetic quote bodies and test certificate
chains. They are not TDX/SNP hardware quotes. Protected key generation, actual
quote capture and hardware adapters remain to be qualified. The native-SNP
provisioning CLI and HTTP server configuration are not migrated; holder/runtime
services must explicitly adopt the new API on both provisioning and release
hops. Upgrading the library alone does not migrate a deployment.

## Wire format and key derivation

Profile: `mlkem768-x25519-sha3-256-aes256gcm-v1`.
The binary envelope version is **2**, reserving version 1 for the earlier local
X-Wing experiment. Old hybrid descriptors, envelopes and private encodings are
refused. There is no automatic conversion. The existing classical format is
unchanged and remains a separate API.

| Object | Encoding |
| --- | --- |
| Private key | `WCMK` + `02` + ML-KEM seed (64 bytes, d then z) + X25519 private bytes (32): **101 bytes** |
| Public descriptor D | `WCMH` + `02` + ML-KEM public key (1184) + X25519 public key (32): **1221 bytes** |
| Encapsulation C | ML-KEM ciphertext (1088) + ephemeral X25519 public key (32): **1120 bytes** |
| Header H | `WCMH` + `02` + C + 12-byte nonce: **1137 bytes** |
| Sealed envelope | H + AES-256-GCM ciphertext + full 16-byte tag: **1153 bytes + payload** |

All sizes above are fixed except payload and caller AAD. `02` denotes one byte.
Private and public prefixes are deliberately different.

```text
Z         = ss_M (32 bytes) || ss_X (32 bytes)
domain    = ASCII("wcm/sealed-key/mlkem768-x25519-sha3-256-aes256gcm/v1") || 00
FixedInfo = C || D || domain || uint32_be(256)
AES_key   = SHA3-256(uint32_be(1) || Z || FixedInfo)
AEAD_AAD  = H || D || caller_aad
```

`ConcatKDFHash` supplies the required one-step counter. ML-KEM comes first in Z;
the ordering, domain, output length, both ciphertext components and both public
keys are fixed by this profile. The counter is explicit rather than omitted
from the simplified combiner notation. Tests check this encoding with an
independent `hashlib` oracle and check both directions of envelope compatibility.
This oracle is a test implementation, not an independent security review.

Each seal generates a fresh native ML-KEM encapsulation, fresh ephemeral X25519
key and random 96-bit GCM nonce. Nonce reuse under the same AES key must never
be introduced by caching or retry logic. There is no reusable traffic key here.
The present OS/backend RNG configuration has not undergone FIPS validation.

X25519 low-order/all-zero shared secrets are refused by the native backend.
ML-KEM coefficient checks occur before encapsulation. A changed ML-KEM
ciphertext may yield an implicit-rejection secret; the GCM tag check then
refuses it. No unauthenticated plaintext is returned.

## What this does not enforce

The raw sealer does not authenticate the sender, enforce authorization or
thresholds, reject replay, or make ciphertext expire. The caller must authenticate
recipient keys and verify grants, transaction context, replay state and validity.
KBS challenge checks cover its release path, not arbitrary reuse of exported
ciphertext. The two-holder test composes independent brokers in a test harness;
it is not a production holder/grant service.

Possession of the complete recipient private key can decrypt recorded envelopes.
This is not forward secrecy against later full-key compromise. Rotation and
destruction require deployment-specific controls. No all-copy zeroization,
side-channel resistance, hardware qualification or end-to-end PQ guarantee is
established by these software tests.

## FIPS validation boundary

**WCM is not FIPS-validated.** Using standardized algorithms and passing test
vectors are not a module certificate. A specific cryptographic module, version,
operating environment and approved mode must be assessed through an accredited
laboratory and CMVP. Algorithm validation is a separate prerequisite.

CMVP Implementation Guidance D.S permits X25519 as an auxiliary non-approved
component of an approved ML-KEM hybrid, subject to restrictions. The module
must enforce the allowed combinations and shared-secret sequencing and provide
an approved combiner. Standalone X25519 does not thereby become approved.

Here Python orchestrates components and concatenates their shared secrets;
no validated module boundary or approved operating mode has been established.
Pointing this code at a validated OpenSSL provider alone would not establish
validation of that composition.

The practical next step is to identify a validated module whose certificate
and security policy cover the required hybrid service, KDF, AES-GCM and RNG,
then integrate and test within those boundaries. If no suitable service exists,
a dedicated module and laboratory validation are a separate project. The
reference SDK should not claim certification for either route without evidence.

## Reproduction and remaining checks

```sh
python -m pip install --require-hashes -r requirements/dev.txt
python -m pip install --require-hashes -r python/docker/requirements-build.lock
python -m pip install --no-deps --no-build-isolation ./python
cd python
PYTHONPATH=src python -m pytest tests/test_hybrid_seal.py tests/test_hybrid_release.py tests/test_hybrid_nist.py -q
PYTHONPATH=src python -m pytest -q --cov=wcm
python -m mypy src/wcm
python -m bandit -q -c pyproject.toml -r src/wcm
```

On PowerShell set `$env:PYTHONPATH = (Resolve-Path src).Path` before testing.
The native Windows run excluded the Bash/jq workflow test file. The complete
[local Linux matrix](validation/hybrid-key-sealing-linux-2026-11-12.md) subsequently
passed on Python 3.11, 3.12 and 3.13. Repository CI remains a merge gate.

Before merge: independent protocol review, maintainer agreement on the profile,
and the existing Linux CI/version matrix. Before deployment: qualify protected
key storage and quote binding, integrate both transport hops and enforce the
application's authenticated key/grant/rotation/recovery policies.

## Sources

- [NIST FIPS 203, ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).
- [NIST SP 800-227, final September 2025](https://csrc.nist.gov/pubs/sp/800/227/final), section 4.6.
- [NIST SP 800-56C Rev. 2, final August 2020](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final), section 4.1.
- [NIST SP 800-38D, AES-GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final).
- [NIST AES-GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf), AES-256 Example 2.
- [NIST ACVP test vectors](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files/ML-KEM-keyGen-FIPS203). The fixture records the source revision, source checksum and 25 selected test IDs. All fixture seeds are public test data.
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1), X25519 vector.
- [CMVP FIPS 140-3 Implementation Guidance](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf), D.S, version consulted 19 August 2026.
- [CMVP validation process](https://csrc.nist.gov/projects/cryptographic-module-validation-program).
- [Algorithm validation program](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).
