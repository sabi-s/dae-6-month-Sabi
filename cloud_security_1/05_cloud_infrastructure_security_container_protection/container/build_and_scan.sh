#!/bin/bash
# Build both images and scan them with Trivy. The pipeline FAILS if the hardened image has HIGH/CRITICAL findings.
set -euo pipefail
cd "$(dirname "$0")"
docker build -f Dockerfile.insecure -t hvmc-lab-api:insecure .
docker build -t hvmc-lab-api:1.0.0 .
mkdir -p reports
# 1) image vulnerabilities (OS packages + language libraries)
trivy image --scanners vuln --format table -o reports/insecure_vuln.txt hvmc-lab-api:insecure || true
trivy image --scanners vuln --format json  -o reports/hardened_vuln.json hvmc-lab-api:1.0.0
# 2) secrets baked into images
trivy image --scanners secret --format table -o reports/insecure_secret.txt hvmc-lab-api:insecure || true
# 3) Dockerfile misconfiguration (IaC) scan
trivy config --format table -o reports/dockerfile_config.txt .
# 4) CI gate: block the release on HIGH or CRITICAL with a fix available
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 hvmc-lab-api:1.0.0
# 5) SBOM for the record (CycloneDX)
trivy image --format cyclonedx -o reports/hvmc-lab-api.sbom.json hvmc-lab-api:1.0.0
