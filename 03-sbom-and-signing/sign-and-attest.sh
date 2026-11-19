#!/usr/bin/env bash
# Generate an SBOM and a vulnerability summary for an image, then sign the image and
# attach both documents as signed in-toto attestations.
#
#   ./sign-and-attest.sh localhost:5000/kbx/sample-app@sha256:<digest> [report-dir]
#
# Always pass a digest: a signature covers exact bytes, and a tag can be moved.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"

ref="${1:?usage: sign-and-attest.sh <registry/repo@sha256:digest> [report-dir]}"
[[ "$ref" == *@sha256:* ]] || { echo "Refusing to sign a tag. Pass repo@sha256:<digest>." >&2; exit 1; }
name="${ref#*/}"; name="${name%@*}"
out="${2:-$HERE/out/${name//\//_}}"
mkdir -p "$out"
ensure_keys

step "SBOM (syft): CycloneDX and SPDX"
syft --quiet "registry:$ref" -o "cyclonedx-json=$out/sbom.cdx.json" -o "spdx-json=$out/sbom.spdx.json"
echo "    $(jq '.components | length' "$out/sbom.cdx.json") components recorded"

step "Vulnerability scan of the SBOM (grype sbom:)"
grype --quiet "sbom:$out/sbom.cdx.json" -o json > "$out/grype.json"
jq '{
  scanner: {name: "grype", version: .descriptor.version,
            dbBuilt: (.descriptor.db.status.built // .descriptor.db.built // null)},
  scannedAt: .descriptor.timestamp,
  counts: (reduce .matches[] as $m ({critical:0, high:0, medium:0, low:0, negligible:0, unknown:0};
           .[$m.vulnerability.severity | ascii_downcase] += 1)),
  fixable: (reduce (.matches[] | select(.vulnerability.fix.state == "fixed")) as $m
           ({critical:0, high:0, medium:0, low:0, negligible:0, unknown:0};
           .[$m.vulnerability.severity | ascii_downcase] += 1))
}' "$out/grype.json" > "$out/vuln-summary.json"
echo "    counts:  $(jq -c .counts "$out/vuln-summary.json")"
echo "    fixable: $(jq -c .fixable "$out/vuln-summary.json")"

# --tlog-upload=false keeps this lab private: nothing is written to the public
# Rekor transparency log. Verification then needs --insecure-ignore-tlog.
step "cosign sign"
cosign sign --yes --key "$COSIGN_KEY" --tlog-upload=false "$ref" 2>&1 | sed 's/^/    /'

step "cosign attest: SBOM (CycloneDX)"
cosign attest --yes --key "$COSIGN_KEY" --tlog-upload=false \
  --type cyclonedx --predicate "$out/sbom.cdx.json" "$ref" 2>&1 | sed 's/^/    /'

step "cosign attest: vulnerability summary"
cosign attest --yes --key "$COSIGN_KEY" --tlog-upload=false \
  --type "$VULN_PREDICATE_TYPE" --predicate "$out/vuln-summary.json" "$ref" 2>&1 | sed 's/^/    /'

echo "Signed and attested: $ref"
echo "Reports: $out"
