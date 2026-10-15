# syntax=docker/dockerfile:1.7
# HVMC lab-results API - hardened image
# Horizon Valley Medical Center | Author: Sabitha S Karanavar
#
# Best practices applied:
#  1  pinned, minimal base images (slim builder, distroless runtime: no shell, no package manager)
#  2  pin by digest in CI (see build_and_scan.sh) so the base cannot change silently
#  3  multi-stage build: build tools never reach the runtime image
#  4  non-root user (distroless "nonroot", UID 65532)
#  5  COPY not ADD; only the files the app needs (.dockerignore excludes the rest)
#  6  no secrets in the image: configuration comes from the runtime environment / Key Vault
#  7  exec-form ENTRYPOINT (signals reach the app, clean shutdown)
#  8  HEALTHCHECK equivalent supplied by the orchestrator probe (/healthz); distroless has no curl
#  9  OCI labels for provenance; read-only root filesystem at runtime (see run_secure.sh)

ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim-bookworm AS build
WORKDIR /src
COPY app/app.py .
# syntax check at build time; the app uses the standard library only, so there is nothing to pip-install
RUN python -m py_compile app.py

FROM gcr.io/distroless/python3-debian12:nonroot
LABEL org.opencontainers.image.title="hvmc-lab-api" \
      org.opencontainers.image.vendor="Horizon Valley Medical Center" \
      org.opencontainers.image.authors="Sabitha S Karanavar" \
      org.opencontainers.image.source="https://github.com/sabi-s/dae-6-month-Sabi"
WORKDIR /app
COPY --from=build --chown=65532:65532 /src/app.py /app/app.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APP_VERSION=1.0.0
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["python3", "/app/app.py"]
