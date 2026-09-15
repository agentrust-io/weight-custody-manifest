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
