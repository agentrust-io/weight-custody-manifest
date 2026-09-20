# Provisioned broker receiver service

`wcm.broker_server` runs the native-SNP receiver lifecycle over HTTP. It starts
without model keys and accepts only an owner-authenticated sealed provisioning
envelope. It uses the `server` package extra and does not read
`WCM_KEYSTORE_FILE`. The original `wcm.server` remains a separate mounted-key
reference service.

## Configuration and startup

Set `WCM_BROKER_CONFIG_FILE` to a JSON document with exactly two top-level fields:
`configuration` and `policy`. Certificate paths and the public-key path are
relative to that file. All are read once at startup.

```json
{
  "configuration": {
    "cpu_root_file": "cpu-root.pem",
    "cpu_vcek_file": "workload-vcek.pem",
    "cpu_intermediate_files": ["cpu-ask.pem"],
    "trusted_manifest_identities": ["sha256:<approved-manifest-identity>"],
    "owner_public_key_file": "owner-ed25519.pub",
    "gpu_root_file": "nvidia-device-root.pem"
  },
  "policy": {
    "measurement_hex": "<approved-broker-48-byte-SNP-measurement-as-96-hex-characters>",
    "configuration_sha256": "<approved-effective-configuration-digest>",
    "weights_hash": "sha256:<approved-weight-artifact-digest>",
    "epoch": 1,
    "guest_policy": 0,
    "minimum_tcb_le_hex": "<owner-chosen-eight-byte-TCB-floor-as-16-hex-characters>",
    "required_platform_fields": ["ciphertext_hiding_en", "alias_check_complete"],
    "forbidden_platform_fields": ["smt_en"]
  }
}
```

Replace every placeholder with independently approved values. `guest_policy: 0`
is illustrative, not a recommended hardware policy; choose the exact acceptable
guest-policy word for the deployment, with DEBUG disabled. Select the TCB floor
for the CPU generation. `owner-ed25519.pub` contains the raw 32-byte public key,
not a private signing key. Certificates are PEM and normalized to DER for the
effective configuration hash. Omit `gpu_root_file` for CPU-only workloads; GPU
claims will then be refused. Unknown or duplicate JSON fields are rejected.

The owner approves `BrokerEffectiveConfiguration.digest()` for these actual
inputs. Startup constructs the receiver from those same inputs and refuses an
owner-policy digest mismatch. No model key belongs in this JSON or any receiver
environment variable.

```bash
export WCM_BROKER_CONFIG_FILE=/run/wcm/broker.json
uvicorn wcm.broker_server:app_from_env --factory --workers 1 --host 127.0.0.1 --port 8080
```

Use one process per broker instance: each process has a different boot key and
provisioning state. Run on a native SEV-SNP guest exposing `/dev/sev-guest`.
Azure vTPM-backed SNP and software providers are not substitutes for this path.

### Container target

Build the explicit receiver target; the default Docker build retains the
mounted-key reference entry point:

```bash
docker build --target provisioned -f python/docker/Dockerfile -t wcm-broker .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8080:8080 -v "$PWD/approved-config:/run/wcm:ro" \
  -e WCM_BROKER_CONFIG_FILE=/run/wcm/broker.json wcm-broker
```

This deliberately omits device access: on an ordinary host, health succeeds but
provisioning reports fail with 503. On an approved native-SNP guest, the deployment
must grant the broker user narrowly scoped access to `/dev/sev-guest` and expose
that device to the container. Do not grant `--privileged` or change to root just
to bypass an access failure. Device permissions, the guest kernel and launcher
are part of the trusted deployment and must be approved with the image.

CI exercises the installed image using synthetic public configuration, verifies
missing-hardware denial, UID 10001, no effective capabilities, no-new-privileges
and read-only root configuration. It builds both targets twice and retains
filesystem/runtime-configuration snapshots. These are same-runner build and
container observations, not evidence of SNP-protected execution. The snapshot
SHA256 is not an SNP launch measurement or an OCI digest. A measured deployment
must bind the selected command, effective configuration and runtime overrides;
reproducible image files alone do not supply that binding.

The [owner provisioning client](owner-provisioning-client.md) performs the
challenge, independent report verification and sealed installation exchange:
`python -m wcm.owner_provision owner.json`. HTTPS is required by default;
`--allow-loopback-http` is reserved for local development. Its guide documents
the separate owner configuration and effective-configuration digest command.

## Protocol

| Endpoint | Request | Response |
|---|---|---|
| `GET /health` | None | `{"status":"ok"}`; availability only |
| `POST /provisioning/report` | `nonce`, `issued_at`, `expires_at` | `report_b64`, `transport_public_key` |
| `POST /provisioning/install` | `nonce`, `ciphertext_b64`, `owner_signature_b64` | `{"installed":true}` |
| `POST /challenge` | None | `nonce`, `issued_at`, `expires_at` |
| `POST /release` | `manifest`, `evidence` | `released`, `sealed_key_b64`, `checks` |

The owner generates the challenge. Its nonce is 64 lowercase hex characters;
times are ISO 8601 strings with UTC offsets. The report endpoint computes
REPORT_DATA using the receiver's own configuration, policy and boot key, then
calls the native device adapter. It cannot accept externally supplied report
bytes or REPORT_DATA. Missing hardware returns HTTP 503 without fallback.

The owner independently verifies the returned report and creates the signed
sealed envelope. Base64 fields use canonical padded standard base64. The
install endpoint verifies the owner, pending challenge, exact policy and boot
key before installing one AES key. Success returns an acknowledgment; it is not
a cryptographic proof of installation. A failed cryptographic install consumes
that pending request. Successful installation disables further provisioning.

Challenge/release return HTTP 409 before provisioning or after retirement.
Requests in the wrong lifecycle state also return 409. Invalid wire shapes
return 422; stale challenges and rejected cryptographic envelopes return 400.
Validation responses omit submitted values. Model-key release returns only
ciphertext bound to an attested workload key. The workload measurement and
verifier profile are described in [deployment trust](deployment-trust.md).

## Deployment boundary

This runnable service does not supply a measured image, protected process
memory, secure erasure or host-independent configuration. Those must be
provided by the deployment approved by the owner. Keep the receiver's code,
configuration, clock and key state inside that protected boundary.

HTTP ingress authentication, TLS termination, request-size/rate limits and
availability controls are deployment responsibilities. In particular, an
unauthenticated caller can consume or replace pending provisioning requests;
cryptographic owner authentication prevents unauthorized key installation but
does not prevent denial of service. Restrict provisioning ingress to the owner.
Do not log request bodies or raw attestation reports. No administrative
retirement or configuration-mutation endpoint is exposed.

Tests use `TestClient` and synthetic signed SNP reports. They establish the HTTP
and receiver behavior without a new live hardware claim.

See [Provisioning lifecycle and recovery](provisioning-lifecycle.md) for the
restart, uncertain-outcome, storage and worker-stop contract and executable
software controls.
