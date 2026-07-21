# Reproducible reference KBS image

The reference key-release-service image that SPEC.md sections 3.4 / 8.3 call for.
Its purpose is **auditability**: built reproducibly, its measurement can be
pinned in a manifest's `custody.kbs_image.measurement` and independently
reproduced by any party, so trust moves from the operator's word to a value
anyone can recompute.

## Build

From the repo root:

```bash
docker build -f python/docker/Dockerfile -t wcm-kbs .
```

## Run

Keys are supplied at **runtime**, never baked into the image. Mount a keystore
(a JSON object mapping `weights_hash` → base64 decryption key) and point
`WCM_KEYSTORE_FILE` at it:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/keystore.json:/run/secrets/keystore.json:ro" \
  -e WCM_KEYSTORE_FILE=/run/secrets/keystore.json \
  wcm-kbs
# GET /health, POST /challenge, POST /release
```

`/release` returns the key in the response body for the reference server — a
production KBS wraps it to the requesting enclave's attested transport instead
(see `wcm/server.py`). Do not expose this image as-is on an untrusted network.

## Reproducibility, honestly

CI (`.github/workflows/kbs-image.yml`) builds the image, runs it, and
health-checks it on every change, so "it builds and serves" is verified. Two
further steps give **bit-for-bit** reproducibility, which a manifest's
`kbs_image.measurement` ultimately depends on:

1. **Pin the base image by digest.** Pass `--build-arg BASE=python:3.12-slim-bookworm@sha256:<digest>`
   so the base cannot drift.
2. **Hash-lock the dependencies.** `docker/constraints.txt` pins the direct
   crypto/framework deps to validated versions; for a full lock, generate a
   hash-pinned requirements set in the target platform
   (`pip-compile --generate-hashes`) and install with `--require-hashes`.

With both, two independent builders produce the same image digest, and that
digest is the value a builder pins and a customer (or a sovereign's accreditation
body) recomputes to verify the running KBS is the certified one — the trust move
in section 8.3.

## What the image is not

- Not a hardware root of trust. The image measurement attests *which KBS code*
  runs; that it runs inside an attested enclave is the deployment's job
  (`custody.kbs_image` is verified in the enclave's attestation, SPEC 3.5).
- Not a production key manager. The runtime keystore mount is a reference
  mechanism; real deployments source keys from a KMS/HSM.
