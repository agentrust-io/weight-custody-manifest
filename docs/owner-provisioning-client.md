# Owner-side provisioning client

The owner client authenticates a fresh native-SNP broker report before sending
an owner-signed, sealed model-key envelope. The model key and signing private key
stay on the owner host; neither is sent as a plaintext HTTP field. The receiver
service is described in [Provisioned broker service](provisioned-broker-service.md).

Run the client on a trusted owner machine with the WCM package installed. Its
configuration, key files, epoch database and namespace must be protected from
the broker operator and from rollback. This is a reference client, not a KMS or
a protected key-storage implementation.

## Configuration

An owner JSON configuration requires these fields:

```json
{
  "policy_file": "approved-policy.json",
  "owner_signing_key_file": "owner-private.raw",
  "amd_root_file": "amd-root.pem",
  "broker_vcek_file": "broker-vcek.pem",
  "broker_intermediate_files": ["amd-ask.pem"],
  "model_key_file": "model-key.raw",
  "epoch_database": "owner-epochs.sqlite",
  "epoch_namespace": "broker-production",
  "broker_url": "https://broker.example"
}
```

Paths are relative to this JSON file. The Ed25519 signing key is 32 raw private
bytes; the model key is 16, 24 or 32 raw bytes. Certificates are PEM. The AMD root
must come from an independently trusted source. Supply the VCEK and intermediate
chain appropriate to the broker; the client verifies their signatures and chain
against that root. Certificate presence alone is not approval.

The optional `deployment_approval_file` and `deployment_approval_identity` fields
must appear together. They pin a separately approved build/launch/policy record
before any broker request. See [Broker deployment identity](broker-deployment-identity.md)
for derivation, substitution checks and the provisional hardware adapter.

`approved-policy.json` contains the exact `BrokerProvisioningPolicy` fields:
`measurement_hex`, `configuration_sha256`, `weights_hash`, `epoch`, `guest_policy`,
`minimum_tcb_le_hex`, `required_platform_fields`, and `forbidden_platform_fields`.
Platform fields are JSON string arrays. The image measurement, TCB floor and
platform requirements must come from the owner's approval process. Do not fill
them from a report merely because that report arrived during provisioning.

The broker configuration format is in the service guide. Compute its digest
from the actual approved certificate bytes, owner public key, manifest identities
and fixed verifier profile:

```sh
python -m wcm.provisioning_wire approved-broker.json
```

This command computes a candidate digest; it does not approve a deployment. The
input policy must be structurally valid, but its existing configuration digest
is not used to compute the candidate. The owner reviews the effective inputs and
places the approved result into both policy copies. The broker factory refuses
to start when the local effective configuration differs. Bind that factory,
configuration and code to the measured deployment; a mutable host can otherwise
replace them. A container digest alone is not an SNP launch measurement.

## Execute once

```sh
python -m wcm.owner_provision owner.json
```

The client first admits the approved policy through the durable owner epoch
guard, then issues a fresh challenge. It asks the broker to collect native SNP
evidence bound to its boot key and configuration. Only after authenticating that
evidence and applying owner policy does it send the sealed envelope for installation.
Responses are size-limited, redirects and environment proxies are disabled, and
there is no automatic retry. TLS uses the normal verified system trust context;
there is no insecure-TLS option.

For a local development service only, `--allow-loopback-http` permits HTTP to
`localhost` or a literal loopback IP. It does not permit plaintext HTTP to remote
hosts. Synthetic loopback tests exercise the wire path but do not establish
hardware protection.

On acknowledgement, the client prints a minimized JSON receipt with the policy
and report digests, epoch, `broker_acknowledged: true` and
`installation_proven: false`. It also reports the optional deployment approval
identity and `application_identity_established: false`; record consistency is
not measured execution evidence. A server acknowledgement is not an attested proof
that installation occurred. On failure the CLI prints only the exception type
and an unknown-outcome message; it does not echo file contents, upstream error
bodies or private keys. Protect receipts because report digests can be linkable.

If a timeout occurs after sending the envelope, the broker may already have
installed it. Do not automatically replay or restart provisioning. Reconcile
the deployment through its separately authenticated control plane. The reference
API intentionally has no remote retirement or status-proof endpoint.

## Remaining deployment work

The service has one in-memory receiver per process. Its management ingress needs
operator access controls and rate/body limits: an unauthenticated caller can
consume or replace pending challenges and cause denial of service. Envelopes
authenticate the owner and report appraisal authenticates the recipient key;
these checks do not provide availability or authenticate ordinary HTTP clients.

Use one worker per broker instance. Process restart requires fresh provisioning
with a fresh boot key. Protect native-SNP device access, the image and effective
configuration, clocks and guest privileges. The epoch store must reside on
trusted nonsnapshot owner storage. Policy advancement does not erase a key from
an already provisioned receiver. Secure erasure, recovery, revocation, firmware
currency and protected CPU/GPU model execution still need separate evidence.

See [Provisioning lifecycle and recovery](provisioning-lifecycle.md) for the
restart, uncertain-outcome, storage and worker-stop contract and executable
software controls.
