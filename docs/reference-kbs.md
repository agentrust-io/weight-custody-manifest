# Reference KBS image

The reference key-release service that §3.4 / §8.3 call for - built reproducibly
so its measurement can be pinned in a manifest's `custody.kbs_image.measurement`
and independently reproduced. Full details:
[`python/docs/reproducible-kbs-image.md`](https://github.com/agentrust-io/weight-custody-manifest/blob/main/python/docs/reproducible-kbs-image.md).

## Server

`wcm.server.create_app(kbs)` is a FastAPI surface (`POST /challenge`,
`POST /release`, `GET /health`) with the same semantics as the library
`KeyBrokerService`. Install with `pip install ".[server]"`.

## Image

```bash
docker build -f python/docker/Dockerfile -t wcm-kbs .
docker run --rm -p 8080:8080 \
  -v "$PWD/keystore.json:/run/secrets/keystore.json:ro" \
  -e WCM_KEYSTORE_FILE=/run/secrets/keystore.json wcm-kbs
```

Keys are supplied at runtime, never baked into the image. CI builds, runs, and
health-checks the image on every change. Bit-for-bit reproducibility additionally
requires pinning the base image by digest and hash-locking dependencies (the
operator hardening steps, documented in the link above).

!!! note "Reference-only deployment"
    The reference server requires channel binding and returns only
    `sealed_key_b64`, encrypted to the transport public key bound into the
    attestation evidence; it never returns the raw key. Production deployments
    must additionally isolate the KBS trust boundary, authenticate clients,
    source keys from a KMS/HSM-backed mounted secret, restrict network ingress,
    and attest/pin the KBS image itself. Do not expose the reference image
    directly on an untrusted network.
