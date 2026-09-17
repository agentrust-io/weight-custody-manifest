# Reference KBS image

The reference key-release service that §3.4 / §8.3 call for - built reproducibly so its measurement can be pinned in a manifest's `custody.kbs_image.measurement` and independently reproduced. Full details: [`python/docs/reproducible-kbs-image.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/docs/reproducible-kbs-image.md).

## Server

`wcm.server.create_app(kbs)` is a FastAPI surface (`POST /challenge`, `POST /release`, `GET /health`) with the same semantics as the library `KeyBrokerService`. Install with `pip install ".[server]"`.

## Image

This example trusts the host administrator with the mounted keys, trust roots, and manifest allowlist. It is not a deployment for protecting weights from that administrator. Read the [deployment trust checklist](https://wcm.agentrust-io.com/deployment-trust/index.md) before provisioning model keys.

```
docker build -f python/docker/Dockerfile -t wcm-kbs .
docker run --rm -p 8080:8080 \
  -v "$PWD/keystore.json:/run/secrets/keystore.json:ro" \
  -v "$PWD/cpu-root.pem:/run/trust/cpu-root.pem:ro" \
  -v "$PWD/gpu-root.pem:/run/trust/gpu-root.pem:ro" \
  -v "$PWD/manifest-identities.json:/run/trust/manifest-identities.json:ro" \
  -e WCM_KEYSTORE_FILE=/run/secrets/keystore.json \
  -e WCM_CPU_TRUST_ROOT_FILE=/run/trust/cpu-root.pem \
  -e WCM_GPU_TRUST_ROOT_FILE=/run/trust/gpu-root.pem \
  -e WCM_TRUSTED_MANIFEST_IDENTITIES_FILE=/run/trust/manifest-identities.json wcm-kbs
```

Keys are supplied at runtime, never baked into the image. CI builds, runs, and health-checks the image on every change. Bit-for-bit reproducibility additionally requires pinning the base image by digest and hash-locking dependencies (the operator hardening steps, documented in the link above).

Reference-only deployment

The reference server requires channel binding and returns only `sealed_key_b64`, encrypted to the transport public key bound into the attestation evidence; it never returns the raw key. Production deployments must additionally isolate the KBS trust boundary, authenticate clients, protect key provisioning from host administrators, restrict network ingress, and attest/pin the KBS image itself. Do not expose the reference image directly on an untrusted network.

A KMS/HSM-backed secret mounted as plaintext remains readable by an administrator controlling that host. Image pinning alone does not protect mounted policy or keys; the owner must verify the provisioning boundary.

The environment-built server fails closed when `WCM_CPU_TRUST_ROOT_FILE` is absent: health and challenge issuance remain available, but every release is denied rather than falling back to structural CPU evidence. The server also fails closed unless the submitted manifest is authorized. `WCM_TRUSTED_MANIFEST_IDENTITIES_FILE` must contain a JSON array of exact `sha256:` manifest identities produced by `wcm.manifest_identity`. The manifest embedded in a release request is never accepted as its own trust anchor.

GPU evidence also requires a cryptographic verifier. Set `WCM_GPU_TRUST_ROOT_FILE` to the reviewed NVIDIA device identity root PEM. Without that root, any request containing GPU evidence is denied. A CPU-only manifest without GPU evidence remains supported. This verifies the GPU report's certificate chain, signature and challenge nonce; it does not establish a protected CPU-to-GPU transfer path or verify RIM claims.
