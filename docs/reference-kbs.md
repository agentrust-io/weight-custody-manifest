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

!!! note "Reference-only release path"
    The reference server returns the key in the `/release` response body. A
    production KBS wraps it to the requesting enclave's attested transport
    instead. Do not expose the reference image as-is on an untrusted network.
