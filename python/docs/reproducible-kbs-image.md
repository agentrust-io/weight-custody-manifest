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

`/release` returns the key in the response body for the reference server, a
production KBS wraps it to the requesting enclave's attested transport instead
(see `wcm/server.py`). Do not expose this image as-is on an untrusted network.

## Reproducibility

Every input to the build is fixed, so two builds of the same source produce the
same filesystem. That is what makes `kbs_image.measurement` worth pinning: a
measurement nobody else can arrive at is a number, not evidence.

1. **The base image is pinned by digest**, not by a moving tag (`BASE_DIGEST` in
   the Dockerfile, the multi-arch index digest for `python:3.12-slim-bookworm`).
   Dependabot moves it, since a digest pin does not pick up security updates on
   its own.
2. **Every dependency is hash-locked.** `docker/requirements.lock` (runtime) and
   `docker/requirements-build.lock` (builder stage) are installed with
   `pip --require-hashes`, so a substituted or re-uploaded artifact fails the
   build instead of quietly changing the image. Both list *every* artifact PyPI
   publishes for each pinned version, so the lock is not tied to one wheel tag.
   Regenerate with `python tools/gen_kbs_lock.py` (`--check` to detect
   staleness); it resolves for the image's platform rather than the host's.
3. **The wheel is built with `--no-build-isolation`** against that locked build
   set, so there is no unpinned network fetch anywhere in the build, and the
   builder stage is discarded so no build tooling reaches the runtime image (CI
   asserts `import hatchling` fails there).
4. **mtimes are normalized to `SOURCE_DATE_EPOCH`.** pip and hatchling stamp
   build time into what they write, and a layer digest covers mtimes, so without
   this two identical builds differ. It happens *inside* each layer that writes
   files, because a layer's digest is sealed when that layer is created, and it
   is scoped to the paths the build actually touches: a blanket `find /` would
   copy every base-image file it touched up into the final layer and balloon the
   image.

### What CI proves, and what it does not

`.github/workflows/kbs-image.yml` builds the image, runs it, health-checks
`/health` and `/challenge`, asserts no build tooling leaked in, then **builds a
second time with `--no-cache` and requires identical layer digests**. It compares
`RootFS.Layers`, not the image id: the image config carries a `created` timestamp
taken from wall-clock, so image ids differ by design while the filesystem should
not.

Being precise about the strength of that check:

- **It does prove** the build does not depend on when it ran, on cached layers,
  or on whatever versions a resolver would have picked that day. Those are the
  failure modes that actually bite.
- **It does not prove** cross-machine reproducibility. Both builds run on one
  runner, with one Docker version, from one checkout. A different BuildKit
  version can lay out layers differently, and `COPY` carries source-file mtimes,
  which a fresh clone elsewhere may set differently.

So the honest claim is: reproducible under a fixed builder, with every *content*
input pinned. Verifying it across independent builders is the remaining step, and
it belongs to whoever is certifying a deployment rather than to CI.

The measurement a builder pins and a customer (or a sovereign's accreditation
body) recomputes is what makes the running KBS checkable against the certified
one, the trust move in section 8.3.

## What the image is not

- Not a hardware root of trust. The image measurement attests *which KBS code*
  runs; that it runs inside an attested enclave is the deployment's job
  (`custody.kbs_image` is verified in the enclave's attestation, SPEC 3.5).
- Not a production key manager. The runtime keystore mount is a reference
  mechanism; real deployments source keys from a KMS/HSM.
