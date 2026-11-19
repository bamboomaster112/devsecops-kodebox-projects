#!/usr/bin/env bash
# Project 03, end to end: build, push, SBOM, scan, sign, attest, verify, then try to
# break it (move a tag, ship a vulnerable image) and watch verification catch it.
#
#   ./pipeline.sh
#
# It also leaves the registry ready for project 05 (Kubernetes admission).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$HERE/common.sh"

APP="$REGISTRY_HOST/kbx/sample-app"
declare -a RESULTS=()
check() {  # check <label> <expected> <actual>
  local s=PASS; [[ "$2" == "$3" ]] || s=FAIL
  RESULTS+=("$s|$1|expected $2, got $3"); printf '    [%s] %s\n' "$s" "$1"
}
verdict() { "$HERE/verify.sh" "$1" >"$2" 2>&1 && echo verified || echo rejected; }
banner() { printf '\n\033[1;35m=== %s ===\033[0m\n' "$*"; }
mkdir -p "$HERE/out"

banner "1. Registry"
"$HERE/registry.sh" up

banner "2. Build and push the hardened image (project 01)"
docker build -q -t "$APP:1.0.0" "$ROOT/01-image-hardening/hardened" >/dev/null
docker push -q "$APP:1.0.0" >/dev/null
REF="$(digest_ref "$APP:1.0.0")"
echo "    $REF"
# Same digest under :latest, so project 05 can show the latest-tag policy on a signed image.
docker tag "$APP:1.0.0" "$APP:latest" && docker push -q "$APP:latest" >/dev/null

banner "3. SBOM, scan, sign and attest"
"$HERE/sign-and-attest.sh" "$REF" "$HERE/out/sample-app-1.0.0"

banner "4. Verify the signed image"
check "hardened image passes signature, SBOM and vuln policy" verified "$(verdict "$REF" "$HERE/out/verify-good.txt")"
sed 's/^/  /' "$HERE/out/verify-good.txt"

step "What is attached to the image (cosign tree)"
cosign tree "$REF" 2>/dev/null | sed 's/^/    /' || true

banner "5. Tamper test: someone pushes different bytes under the same tag"
tmp="$(mktemp -d)"
printf 'FROM %s\nLABEL tampered="true"\n' "$APP:1.0.0" > "$tmp/Dockerfile"
docker build -q -t "$APP:1.0.0" "$tmp" >/dev/null && rm -rf "$tmp"
docker push -q "$APP:1.0.0" >/dev/null
check "moved tag :1.0.0 is rejected" rejected "$(verdict "$APP:1.0.0" "$HERE/out/verify-tampered.txt")"
check "original digest still verifies" verified "$(verdict "$REF" /dev/null)"
step "Restoring :1.0.0 to the signed digest"
docker pull -q "$REF" >/dev/null
docker tag "$REF" "$APP:1.0.0" && docker push -q "$APP:1.0.0" >/dev/null
check "restored tag points at the signed digest" yes "$([[ "$(digest_ref "$APP:1.0.0")" == "$REF" ]] && echo yes || echo no)"

banner "6. Signed is not the same as safe: the legacy image from ~/devsecops"
SAMPLE_APP_DIR="${SAMPLE_APP_DIR:-$HOME/devsecops}"
docker build -q -t "$APP:0.9.0-legacy" "$SAMPLE_APP_DIR" >/dev/null
docker push -q "$APP:0.9.0-legacy" >/dev/null
LEGACY="$(digest_ref "$APP:0.9.0-legacy")"
"$HERE/sign-and-attest.sh" "$LEGACY" "$HERE/out/sample-app-0.9.0-legacy" >/dev/null
echo "    legacy counts: $(jq -c .counts "$HERE/out/sample-app-0.9.0-legacy/vuln-summary.json")"
check "signed legacy image fails the vuln policy" rejected "$(verdict "$LEGACY" "$HERE/out/verify-legacy.txt")"
grep -E 'PASS|FAIL' "$HERE/out/verify-legacy.txt" | sed 's/^/  /'

banner "7. An image that was never signed"
docker tag "$APP:1.0.0" "$REGISTRY_HOST/kbx/unsigned-app:1.0.0"
docker push -q "$REGISTRY_HOST/kbx/unsigned-app:1.0.0" >/dev/null
check "unsigned image is rejected" rejected \
  "$(verdict "$(digest_ref "$REGISTRY_HOST/kbx/unsigned-app:1.0.0")" "$HERE/out/verify-unsigned.txt")"

printf '\n\033[1m%-6s %-55s %s\033[0m\n' RESULT CHECK DETAIL
fails=0
for r in "${RESULTS[@]}"; do
  IFS='|' read -r s label detail <<<"$r"
  printf '%-6s %-55s %s\n' "$s" "$label" "$detail"
  [[ "$s" == PASS ]] || fails=$((fails + 1))
done
echo "Public key for verifiers (project 05): $KEY_DIR/cosign.pub"
exit "$fails"
