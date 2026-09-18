# Reproducible reference KBS image

The reference key-release-service image that SPEC.md sections 3.4 / 8.3 call for.
Its purpose is **auditability**: a builder can retain and compare exact image
content and runtime configuration. Binding an approved image to a hardware
launch and the running broker is a separate deployment requirement.

## Build

From the repo root:

```bash
docker build -f python/docker/Dockerfile -t wcm-kbs .
```

## Provisioned target

```bash
docker build --target provisioned -f python/docker/Dockerfile -t wcm-broker .
```

This target starts `wcm.broker_server:app_from_env` with one worker. It accepts
`WCM_BROKER_CONFIG_FILE` and starts without model keys; provisioning uses the
owner-authenticated envelope protocol. The default build still starts the
mounted-key reference service. See the [provisioned service guide](../../docs/provisioned-broker-service.md)
for configuration and runtime restrictions. Neither target itself supplies an
immutable, hardware-measured guest image.

## Run the mounted-key reference

This is a reference-only deployment. The host administrator can read the
mounted key file and replace trust configuration. It does not protect model
keys from that administrator or implement the attested self-custody design.
See the [deployment trust checklist](../../docs/deployment-trust.md).

Keys are supplied at **runtime**, never baked into the image. Mount a keystore
(a JSON object mapping `weights_hash` → base64 decryption key) and point
`WCM_KEYSTORE_FILE` at it:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/keystore.json:/run/secrets/keystore.json:ro" \
  -v "$PWD/cpu-root.pem:/run/trust/cpu-root.pem:ro" \
  -v "$PWD/manifest-identities.json:/run/trust/manifest-identities.json:ro" \
  -e WCM_KEYSTORE_FILE=/run/secrets/keystore.json \
  -e WCM_CPU_TRUST_ROOT_FILE=/run/trust/cpu-root.pem \
  -e WCM_TRUSTED_MANIFEST_IDENTITIES_FILE=/run/trust/manifest-identities.json \
  wcm-kbs
# GET /health, POST /challenge, POST /release
```

`/release` returns only `sealed_key_b64`, encrypted to the transport key bound
into the attestation evidence, never the raw key (see `wcm/server.py`). The
environment-built server denies release without a configured CPU trust root
and a pinned manifest identity. The identity file is a JSON array of exact
`sha256:` identities from `wcm.manifest_identity`; authorize manifests out of
band before pinning them. Sealing the HTTP response does not protect the
plaintext source key file from the host. Do not expose this image as-is on an
untrusted network.

## Reproducibility

The build pins its base and dependency inputs and normalizes selected timestamps.
The comparison below tests whether two builds match under its stated scope.

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
   staleness); it resolves for the image's platform rather than the host's, and
   from `pyproject.toml`'s own declared requirements, so a pin cannot violate
   what the package says it supports.
3. **The wheel is built with `--no-build-isolation`** against that locked build
   set, so there is no unpinned network fetch anywhere in the build, and the
   builder stage is discarded so no build tooling reaches the runtime image (CI
   asserts `import hatchling` fails there).
4. **mtimes are normalized to `SOURCE_DATE_EPOCH`**, inside each layer that
   writes files, because pip and hatchling stamp build time into what they write.
   It has to happen in the same layer, since a layer's content is sealed when it
   is created, and it is scoped to the paths the build touches: a blanket
   `find /` would copy every base-image file it touched up into the final layer
   and balloon the image.
5. **pip installs with `--no-compile`.** pip byte-compiles by default and a
   `.pyc` embeds the source mtime, so normalizing mtimes *afterwards* leaves
   bytecode holding the pre-normalization value: reproducible-looking sources
   over irreproducible bytecode. `PYTHONDONTWRITEBYTECODE` does not cover this,
   because it governs the interpreter rather than pip's own compile pass. The
   cost is a little startup CPU, since nothing is cached to disk at runtime
   either.

## Verifying it

```bash
./python/docker/verify-reproducible.sh --target reference --output-dir ./image-evidence/reference
./python/docker/verify-reproducible.sh --target provisioned --output-dir ./image-evidence/provisioned
```

Each command builds its selected target twice, with `--no-cache` for the second
build. It exports both filesystems and compares canonical snapshots containing:

- File types, contents, paths, numeric owners/groups and permissions.
- Symlink and hardlink targets, device numbers and non-time PAX metadata,
  including exported extended attributes such as capabilities.
- Image architecture/OS/variant and the complete runtime `Config`, including
  entry point, command, environment, user, working directory and health checks.

An export or parser failure stops the comparison. Exports are parsed without
extracting them or requiring sudo. Duplicate/escaping paths, unresolved
hardlinks, unsupported entries and truncated file contents are refused.

`image-snapshot.json` and `sha256.txt` are retained when `--output-dir` is
provided. The digest identifies this comparison format and its contents. It is
neither an OCI image digest nor an SNP launch measurement. The format is now
`wcm/image-content-and-config/v1`; it is not compatible with the earlier
filesystem-only digest, which omitted link targets, ownership and runtime
configuration. Any consumers of the old reference must recompute and review it.

Timestamps and image history are deliberately excluded. BuildKit can attach
fresh tar timestamps to otherwise identical content. Comparing content and
runtime configuration avoids treating that metadata noise as a changed program,
while retaining fields that change what starts or which privileges/files it has.
This does not mean timestamps are irrelevant to every application or threat
model; deployments that depend on them need a different measurement contract.

### What the comparison establishes

A pass establishes equality of the defined snapshot fields for these two builds
on one runner. It does not prove future builds or independent builders will
match, or that the published source is trustworthy. It also does not appraise
the running host, firmware, VM launch state, mounted configuration or keys.

CI builds both targets, exercises the provisioned image with synthetic public
configuration and no hardware, and retains the comparison snapshots. That smoke
run checks missing-hardware denial and configured container restrictions. It
cannot establish native-SNP key custody or protected model execution.

## What the image is not

- Not a hardware root of trust. The snapshot records image inputs; it does not
  attest that this image is running. Binding image, effective configuration and
  key custody to authenticated hardware evidence is the deployment's job.
- Not a production key manager. The runtime keystore mount is a reference
  mechanism; real deployments need owner-authorized provisioning into a
  protected broker. A KMS/HSM that exports keys to the customer-controlled host
  does not establish that boundary.
