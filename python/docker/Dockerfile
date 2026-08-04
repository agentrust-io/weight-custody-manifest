# Reference Weight Custody Manifest KBS image (SPEC.md sections 3.4 / 8.3).
#
# The point of this image is auditability: its measurement gets pinned in a
# manifest's `custody.kbs_image.measurement`, and a measurement nobody can
# reproduce is not worth pinning. So every input to the build is fixed:
#
#   1. The base image is pinned BY DIGEST, not by a moving tag.
#   2. Every dependency is installed with `pip --require-hashes` from a lock that
#      names every artifact PyPI publishes for that version, so a substituted or
#      re-uploaded artifact fails the build instead of changing the image.
#   3. The wheel is built with --no-build-isolation against a hash-locked build
#      set, so there is no unpinned network fetch anywhere in the build.
#   4. mtimes are normalized to SOURCE_DATE_EPOCH *inside each layer that writes
#      files*, because pip and hatchling stamp build time into what they write and
#      a layer digest covers mtimes. Normalizing in a later layer would not help:
#      each layer's digest is sealed when that layer is created.
#   5. pip installs with --no-compile. pip byte-compiles by default, and a .pyc
#      embeds the source mtime, so normalizing mtimes afterwards leaves .pyc files
#      holding the pre-normalization value: reproducible-looking sources over
#      irreproducible bytecode. PYTHONDONTWRITEBYTECODE does not cover this; it
#      governs the interpreter, not pip's own compile pass.
#
# Layers are deliberately coarse for the same reason: one RUN that installs,
# creates the user, and normalizes is one digest to keep stable, where three RUNs
# would be three.
#
# CI runs docker/verify-reproducible.sh, which builds twice (the second time with
# --no-cache) and compares the EXPORTED FILESYSTEM CONTENT of the two images. See
# docs/reproducible-kbs-image.md for why content rather than layer digests, and
# for what the check does and does not prove (it is a same-runner check, not a
# cross-machine one).
#
# Build from the REPO ROOT:
#   docker build -f python/docker/Dockerfile -t wcm-kbs .
#
# To move the base image, change BASE_DIGEST (and PYTHON_VERSION in
# tools/gen_kbs_lock.py plus SITE_PACKAGES below if the interpreter version
# changes), then regenerate the locks. Dependabot tracks the digest.
#
# Keys are provided at RUNTIME via WCM_KEYSTORE_FILE (a mounted secret), never
# baked into the image.

ARG BASE_IMAGE=python:3.12-slim-bookworm
# python:3.12-slim-bookworm, multi-arch index digest. Immutable.
ARG BASE_DIGEST=sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b
ARG SOURCE_DATE_EPOCH=1700000000

# --------------------------------------------------------------------------
# Builder: build the wcm wheel. None of this reaches the runtime image.
# --------------------------------------------------------------------------
FROM ${BASE_IMAGE}@${BASE_DIGEST} AS builder

ARG SOURCE_DATE_EPOCH
ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

COPY python/ /src/python/
# The manifest JSON Schema and the conformance vectors live at the REPO root and
# the wheel build force-includes them into the package, so the build needs them
# alongside python/.
COPY schema/ /src/schema/
COPY conformance/ /src/conformance/
COPY python/docker/requirements-build.lock /tmp/requirements-build.lock

WORKDIR /src/python
# --no-build-isolation: hatchling comes from the hash-locked set, so the build
# fetches nothing. The wheel's own mtime is normalized here, so the COPY of it
# into the runtime stage lands in a deterministic layer.
RUN pip install --no-cache-dir --no-compile --require-hashes -r /tmp/requirements-build.lock \
    && python -m hatchling build -t wheel -d /wheel \
    && touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" /wheel /wheel/*.whl \
    && ls -l /wheel

# --------------------------------------------------------------------------
# Runtime: hash-locked dependencies plus the built wheel. No build tooling.
# --------------------------------------------------------------------------
FROM ${BASE_IMAGE}@${BASE_DIGEST}

ARG SOURCE_DATE_EPOCH
# Normalization targets. Scoped deliberately: a blanket `find /` would copy every
# base-image file it touched up into this layer and balloon the image.
ARG SITE_PACKAGES=/usr/local/lib/python3.12/site-packages
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /app
COPY python/docker/requirements.lock /tmp/requirements.lock
COPY --from=builder /wheel /tmp/wheel

# One layer: install the locked closure, install the wheel with --no-deps (with
# resolution enabled this would reintroduce an unpinned fetch), create the
# non-root user, then normalize mtimes. The find is wrapped so its failure on a
# missing path cannot mask a pip failure earlier in the chain.
RUN pip install --no-cache-dir --no-compile --require-hashes -r /tmp/requirements.lock \
    && pip install --no-cache-dir --no-compile --no-deps --no-index /tmp/wheel/*.whl \
    && rm -rf /tmp/requirements.lock /tmp/wheel \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin kbs \
    && { find "${SITE_PACKAGES}" /usr/local/bin /etc/passwd /etc/group \
              /etc/shadow /etc/gshadow /etc/subuid /etc/subgid \
              -newermt "@${SOURCE_DATE_EPOCH}" \
              -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} + \
              2>/dev/null || true; }

USER 10001

EXPOSE 8080
CMD ["uvicorn", "wcm.server:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8080"]
