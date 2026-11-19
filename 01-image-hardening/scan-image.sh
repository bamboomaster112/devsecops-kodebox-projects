#!/usr/bin/env bash
# Lint a Dockerfile, build the image, and scan it with every toolkit scanner.
#
#   ./scan-image.sh <build-context> <image:tag> <report-dir>
#
# Writes hadolint.json/txt, trivy.json/txt, grype.json, dockle.json, sbom.cdx.json
# and inspect.json into <report-dir>. It never fails on findings: deciding what
# is "too many" is the job of the CI gate in project 04.
set -euo pipefail

ctx="${1:?usage: scan-image.sh <build-context> <image:tag> <report-dir>}"
image="${2:?image:tag}"
out="${3:?report dir}"
mkdir -p "$out"

step() { printf '\033[1;36m--> %s\033[0m\n' "$*"; }

step "hadolint $ctx/Dockerfile"
# Exit code 1 means "findings", which is expected for the 'before' Dockerfile.
hadolint --no-fail -f json "$ctx/Dockerfile" > "$out/hadolint.json"
hadolint --no-fail "$ctx/Dockerfile" > "$out/hadolint.txt"

step "docker build -t $image $ctx"
docker build -q -t "$image" "$ctx" > /dev/null
docker image inspect "$image" > "$out/inspect.json"

step "trivy image $image (vulnerabilities + secrets)"
trivy image --quiet --scanners vuln,secret --format json --output "$out/trivy.json" "$image"
trivy convert --quiet --format table --output "$out/trivy.txt" "$out/trivy.json"

step "grype $image"
grype --quiet -o json "docker:$image" > "$out/grype.json"

step "dockle $image"
# Accepted checks live in <build-context>/.dockleignore, one code per line with a reason.
ignores=()
if [[ -f "$ctx/.dockleignore" ]]; then
  while read -r code; do ignores+=(--ignore "$code"); done < <(grep -oE '^[A-Z]+-[A-Z]+-[0-9]+' "$ctx/.dockleignore")
fi
dockle "${ignores[@]}" --format json --output "$out/dockle.json" "$image" > /dev/null || true

step "syft $image (SBOM, CycloneDX)"
syft --quiet "docker:$image" -o "cyclonedx-json=$out/sbom.cdx.json"

echo "Reports written to $out"
