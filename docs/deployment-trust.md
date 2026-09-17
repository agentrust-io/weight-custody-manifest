# Who controls key release?

WCM's custody claim requires a release authority the model owner trusts. If the
customer can read the model key or replace the verifier, trust roots, or accepted
policy, workload attestation does not protect the owner from that customer.
Separate administrator teams within the same entity do not establish this
boundary when that entity can override both teams.

This applies to WCM's reference KBS and to integrations with a service such as
Confidential Containers Trustee. WCM does not supply a Trustee integration or
certify a Trustee deployment by checking a manifest.

## Deployment configurations

| Configuration | Custody claim |
|---|---|
| Customer hosts the workload; model owner or an owner-trusted custodian controls protected key release | Consistent with the trust model, conditional on the hardware, workload, and release-service assumptions being met. |
| Customer controls both workload infrastructure and an ordinary KBS/Trustee, including keys or verification settings | Unsupported for protecting the model owner's weights from that customer. |
| Customer hosts a protected KBS whose code, configuration, and provisioning the owner independently verifies | Design direction in SPEC section 3.5; not an end-to-end capability delivered by the reference server. |
| One enterprise owns the model and operates both services | Useful for internal governance, but does not demonstrate protection against an untrusted customer controlling both services. |

Hosting location alone does not decide trust. The relevant question is whether
the customer can obtain a key or change an accepted release decision without
the owner's authorization. An external KMS/HSM does not resolve this if it
exports keys to customer administrators or blindly trusts their verifier.

## Deployment review checklist

Record the responsible principal, configuration, and verification evidence for
each item before provisioning model keys:

- **Key custody:** who can read, export, back up, restore, or provision model
  keys, including mounted secrets and recovery credentials? The customer must
  not have an alternate route to the plaintext key.
- **Verification:** who can replace verifier code, hardware trust roots,
  reference values, accepted measurements, and manifest identities? These must
  remain under owner-approved authority, including after restart and update.
- **Policy authority:** how are builder/custodian signatures and signer identities
  verified before a manifest is accepted? A caller-provided manifest or a
  customer-controlled allowlist is not independent authorization.
- **Release channel:** is the recipient key bound to fresh workload attestation,
  and is the model key released only to that recipient?
- **Administrative overrides:** can cluster, host, KBS, KMS, or recovery admins
  bypass these controls through debug access, replacement images, configuration
  mounts, snapshots, or rollback?
- **Revocation and renewal:** who supplies current policy and revocation state,
  and what prevents stale state or a replacement broker from extending access?
- **Hardware trust:** does the owner accept the TEE roots and relevant physical
  and software attack assumptions for both workload and release service?

An unanswered item is an unresolved deployment assumption. A completed checklist
is a review record, not cryptographic evidence of administrative independence.

## What the reference server actually does

`server.build_kbs_from_env` reads plaintext keys from `WCM_KEYSTORE_FILE`, CPU
trust from `WCM_CPU_TRUST_ROOT_FILE`, and manifest identities from
`WCM_TRUSTED_MANIFEST_IDENTITIES_FILE`. The KBS copies keys into process memory.
Read-only Docker mounts prevent writes through that mount; they do not hide
the source files from the host administrator.

The environment-built server requires CPU quote verification, channel binding,
and an exact pinned manifest identity. Those checks constrain requests to an
intact, trusted broker. They do not constrain an administrator who can replace
the broker or read its key file. `custody.kbs_image` describes the required image;
the reference release path does not attest itself against that field before
loading keys. `/health` reports availability, not custody assurance.

The [reference image](reference-kbs.md) is therefore a protocol demonstration,
not a protected self-custody deployment. See the
[implementation audit](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/docs/threat-model-implementation-audit.md).

## Work required for customer-hosted protected release

Before claiming support, a deployment must demonstrate owner-authorized
provisioning into a freshly attested KBS, with the provisioning channel bound to
that KBS instance. Verification must cover the release code and security-relevant
configuration, including mounted policy and trust data. Merely reproducing an
image digest does not establish this runtime boundary.

Acceptance evidence must include denied provisioning after code, root, policy,
or recipient-key substitution; attempts to read keys through host and recovery
paths; rollback and revocation handling; and successful release only through the
approved KBS to an approved workload. The SDK's threshold sharing primitive does
not implement independent share custodians or their provisioning policies.

These are implementation and deployment follow-ups, not a new claim that nesting
TEEs removes hardware trust. If the owner rejects the underlying TEE assumptions,
attesting a second service does not resolve that objection.

### Owner-side provisioning reference protocol

`wcm.provisioning.OwnerProvisioner` now supplies a native-SNP protocol primitive
for an owner-operated provisioning service. It does not alter the HTTP reference
server's plaintext keystore loading or provide a protected broker image.

The owner pins the broker's raw 48-byte SNP measurement, SHA-256 of its complete
effective configuration, model-key label, update epoch and explicit hardware
requirements in
`BrokerProvisioningPolicy`. Configuration must include verifier selection, trust
roots, accepted manifest identities, platform requirements and override paths.
The protected broker generates its X25519 key internally and computes the digest
from the configuration it will enforce. It requests an SNP report with
`REPORT_DATA[:32] = SHA256(owner_nonce || provisioning_binding(policy, public_key))`.

The owner verifies the pinned certificate chain, report signature, challenge,
configuration/session binding, signed image measurement, exact guest policy,
required/forbidden platform fields and component-wise reported TCB floor before
sealing the model key. Debug-enabled guest policy is rejected unconditionally.
An owner Ed25519 signature authenticates the resulting envelope.
`open_provisioned_key` verifies that signature and the exact policy before
opening it with the broker's transport key. Policy updates must advance the
epoch and invalidate all pending challenges; each attempt consumes its nonce.

This closes protocol-level substitution paths in the reference implementation.
It does not establish that a real runtime measures configuration correctly or
prevents subsequent changes. Deployment still needs an immutable measured broker
boot image, protected memory, secure owner-side persistence, retirement of old
instances and key erasure. The receiver lifecycle and optional persistent epoch
guard below implement software controls for some of these requirements.
The owner must choose the TCB floor in the selected CPU generation's eight-byte
little-endian ABI layout; no default firmware floor is inferred. Required and
forbidden platform fields both reject unavailable version-gated fields. The
guest policy, TCB floor and platform requirements are themselves bound into
attestation and the signed envelope. The TCB byte layouts and DEBUG bit follow
[AMD's SNP ABI](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).
The primitive does not establish revocation or physical-attack resistance.
Those remain admission requirements for the selected threat model.
Azure's vTPM/PCR provisioning adapter is
not implemented by this native-SNP protocol.

`python/tests/test_provisioning.py` uses synthetic SNP signatures and a synthetic
certificate root to exercise image/configuration/root/key substitutions, stale
epochs, replay, expiry and owner/envelope tampering. These tests establish
protocol behavior under the stated assumptions, not live broker isolation.

### Receiver boot lifecycle

`wcm.broker_receiver.BrokerEffectiveConfiguration` snapshots normalized DER CPU
root/VCEK/intermediate certificates, an optional NVIDIA root, exact accepted
manifest identities and the owner's Ed25519 public key. Its digest also commits
the fixed verifier profile, strict channel/CPU/GPU checks and timeout settings.
Construct these inputs from the actual approved configuration; do not accept an
attacker-supplied digest as a substitute. `BrokerReceiver(configuration, policy)`
computes that digest locally and rejects a mismatch with the owner policy.

Each receiver creates a fresh X25519 key internally and starts without model
keys. The native-SNP boot integration is:

```python
receiver = BrokerReceiver(configuration, owner_approved_policy)
challenge = owner.issue_challenge()
report_data = receiver.provisioning_report_data(challenge)
report = SevSnpProvider().provisioning_report(report_data)
# Send report, receiver.transport_public_key and the VCEK chain to the owner.
# The owner independently verifies them and returns a signed sealed envelope.
receiver.install(envelope)
```

The report collector calls the existing `/dev/sev-guest` adapter with no software
fallback. Installation authenticates the owner, exact policy, boot key and
pending nonce. Requests expire locally after at most 60 seconds and cannot be
extended by repeating a nonce. A successful installation constructs the KBS
from the same configuration inputs and permanently closes provisioning for that
receiver. Release is unavailable before installation. A new receiver cannot
open an old boot's envelope. `retire()` permanently disables its release and
provisioning APIs; releasing Python references does not prove memory erasure.

The receiver's native-SNP workload profile uses `sha256:` of the **raw signed
48-byte launch measurement** as the manifest serving-image measurement. It
checks that value after authenticating the report, requires VMPL 0, rejects
debug-enabled workloads, and binds key release to the workload's transport key. This profile
is not an OCI digest or a hash of an arbitrary supplied image name. It uses the
configured VCEK chain; changing that chain requires fresh configuration approval.
GPU evidence without a configured root is denied. GPU firmware RIM appraisal
and protected CPU/GPU transport remain outside this receiver.

The [receiver HTTP service](provisioned-broker-service.md) wraps this boot
lifecycle with native report collection, sealed installation and release
endpoints. Neither the library nor the service supplies a measured broker image.
Python immutability and private attributes do not constrain a host
that can modify the process. The runtime must protect code, configuration, clock
and keys. Workload policy remains the pinned manifest's policy; the receiver
does not add an independently chosen workload TCB floor. Synthetic tests in
`python/tests/test_broker_receiver.py` exercise boot-to-release behavior and
substitution/replay/retirement failures; no new hardware result is implied.
Changes to fixed verifier semantics or defaults require a new configuration
profile version and owner approval of the resulting digest.

### Optional persistent owner epoch guard

Pass `epoch_store=OwnerEpochStore(path, namespace)` from
`wcm.provisioning_state` when constructing `OwnerProvisioner`. The SQLite store
persists the current epoch and policy-context hash. It refuses older epochs and
same-epoch policy substitutions, and guards releases against another owner
process advancing the epoch. Without this option, owner state remains in memory.

The database, its namespace and the owner service must reside on trusted storage
that the customer cannot roll back or replace. SQLite transactions do not make
a hostile disk or VM snapshot trustworthy. Provisioning epoch advances do not
erase keys already provisioned to a broker or revoke their future use; retiring
those brokers and enforcing workload key lifetimes are separate controls.

## CPU-to-GPU confidentiality acceptance

The reference HTTP server requires cryptographic GPU verification whenever GPU
evidence is submitted, using `WCM_GPU_TRUST_ROOT_FILE`. This closes a structural
evidence downgrade. The library retains an explicit development mode; callers
requiring verified GPU reports must set `require_gpu_report_verification=True`.

Shared challenge nonces establish freshness of two reports. They do not by
themselves establish physical co-location or an authenticated encrypted data
path between those devices. NVIDIA report signature verification also does not
compare signed firmware measurements against vendor RIMs. The serving runtime
and vendor verifier must supply those additional assurances.

Before claiming confidential model execution across CPU and GPU, retain:

- Fresh CPU and GPU verification results bound to the receiving workload and
  its session, with approved firmware/driver measurements and CC mode enabled.
- Evidence that the driver establishes the protected device session and that
  model bytes, activations and outputs cross only that protected path, including
  staging buffers and diagnostics.
- Denials after GPU substitution, CC mode disablement, unsupported firmware,
  expired verification collateral and loss of the protected device session.
- An exact-artifact decrypt/load/inference result inside the measured workload,
  followed by revocation or lease-lapse handling.

The existing `python/tools/paired_hardware_release.py` exercises paired quote
verification and sealed key release. It does not run model inference or inspect
the CPU-to-GPU data path. The August 20, 2026 fixture README records a historical
pass, but its `paired-release.json` receipt is not distributed in this checkout;
the retained preflight and README do not independently reproduce that result.
