# Reference Weight Custody Manifest KBS image (SPEC.md sections 3.4 / 8.3).
#
# The point of this image is auditability: it is built reproducibly so its
# measurement can be pinned in a manifest's `custody.kbs_image.measurement` and
# independently reproduced. For bit-for-bit reproducibility, pass the base image
# BY DIGEST (BASE build-arg) and use a fully hash-locked requirements set; this
# Dockerfile pins the direct deps (docker/constraints.txt) and builds
# deterministically. See docs/reproducible-kbs-image.md.
#
# Build from the REPO ROOT:
#   docker build -f python/docker/Dockerfile -t wcm-kbs .
#
# Keys are provided at RUNTIME via WCM_KEYSTORE_FILE (a mounted secret), never
# baked into the image.
ARG BASE=python:3.12-slim-bookworm
FROM ${BASE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=1700000000

WORKDIR /app
COPY python/ /app/python/
# The manifest JSON Schema and the conformance vectors live at the repo root and
# the wheel build force-includes them into the package, so the build needs them
# alongside python/. The schema also belongs in this image on its own merits: the
# KBS validates manifests.
COPY schema/ /app/schema/
COPY conformance/ /app/conformance/
RUN pip install --no-cache-dir -c /app/python/docker/constraints.txt "/app/python[server]"

# Run as a non-root, no-login user.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin kbs
USER 10001

EXPOSE 8080
CMD ["uvicorn", "wcm.server:app_from_env", "--factory", "--host", "0.0.0.0", "--port", "8080"]
