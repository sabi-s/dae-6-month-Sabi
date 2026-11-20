#!/bin/bash
# Run the HVMC lab-results API with least privilege (Docker security settings at container level).
set -euo pipefail
# Docker's default seccomp profile applies automatically (never pass seccomp=unconfined).
# Liveness is checked by the orchestrator probe on /healthz (distroless has no shell for HEALTHCHECK).
IMAGE="hvmc-lab-api:1.0.0"
docker run -d --name hvmc-lab-api \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --user 65532:65532 \
  --pids-limit 100 --memory 256m --memory-swap 256m --cpus 0.50 \
  --network hvmc-app-net \
  -p 127.0.0.1:8080:8080 \
  --restart on-failure:3 \
  --no-healthcheck \
  "$IMAGE"
