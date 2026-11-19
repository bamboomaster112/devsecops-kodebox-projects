#!/usr/bin/env bash
# Verify an image the way a deploy pipeline or admission controller would.
#
#   ./verify.sh <image-ref>           # signature + SBOM attestation + vulnerability policy
#
# Exit code 0 only when all three checks pass.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$HERE/common.sh"
ref="${1:?usage: verify.sh <image-ref>}"
ensure_keys
rc=0

step "cosign verify (signature)"
if cosign verify --key "$COSIGN_PUB" --insecure-ignore-tlog=true "$ref" 2>/dev/null \
    | jq -r '.[0].critical.image."docker-manifest-digest" | "    signed digest: \(.)"'; then
  echo "    PASS"
else
  echo "    FAIL: no valid signature for this key"; rc=1
fi

step "cosign verify-attestation --type cyclonedx (SBOM)"
if sbom="$(cosign verify-attestation --key "$COSIGN_PUB" --insecure-ignore-tlog=true \
            --type cyclonedx "$ref" 2>/dev/null)"; then
  echo "$sbom" | head -1 | jq -r '.payload' | base64 -d \
    | jq -r '"    SBOM lists \(.predicate.components | length) components"'
  echo "    PASS"
else
  echo "    FAIL: no signed SBOM attestation"; rc=1
fi

step "cosign verify-attestation --policy policy/vuln-summary.rego"
if out="$(cosign verify-attestation --key "$COSIGN_PUB" --insecure-ignore-tlog=true \
           --type "$VULN_PREDICATE_TYPE" --policy "$HERE/policy/vuln-summary.rego" "$ref" 2>&1)"; then
  echo "$out" | grep -m1 '^{' | jq -r '.payload' | base64 -d \
    | jq -r '"    critical=\(.predicate.counts.critical) fixable-high=\(.predicate.fixable.high)"'
  echo "    PASS"
else
  echo "$out" | grep -iE 'policy|error' | head -3 | sed 's/^/    /'
  echo "    FAIL: vulnerability policy not met"; rc=1
fi
exit "$rc"
