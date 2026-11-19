# syntax=docker/dockerfile:1
#
# Hardened image for the KodeBox sample app. Each numbered comment maps to a finding
# from the "before" scan of ~/devsecops/Dockerfile (see ../README.md).

# (1) Supported Python on a current Debian base, pinned by tag AND digest so a rebuild
#     cannot silently pick up a different image. Refresh the digest on purpose.
ARG BASE_IMAGE=python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

# ---------- build stage: install dependencies into a virtualenv ----------
FROM ${BASE_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
# (2) Only the lockfile is copied before the install, so this layer is cached
#     until the dependencies change.
COPY requirements.txt .
# (3) --require-hashes: pip refuses any package whose hash is not in the lockfile.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip

# ---------- runtime stage: no compilers, no package caches, no pip ----------
FROM ${BASE_IMAGE} AS runtime
# (4) Apply Debian security fixes published after the base image was built, and remove
#     pip: the app never installs anything at runtime, and pip's vendored libraries
#     (urllib3, msgpack, ...) are the image's only fixable Python CVEs.
# (5) A dedicated, unprivileged user with a fixed UID that Kubernetes can check.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/* \
 && python -m pip uninstall -y pip \
 && groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
# (6) COPY one named file instead of "ADD . /app" (no config.env, no .git).
COPY --chown=root:root --chmod=0444 app.py .
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    APP_ENV=production
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
# (7) Exec-form CMD and a production WSGI server instead of the Flask dev server.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "app:app"]
