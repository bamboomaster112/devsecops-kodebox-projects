#!/usr/bin/env bash
# Run every scanner against one app, then let gate.py decide PASS or FAIL.
#
#   ./gate.sh                          # gate the hardened app from project 01 (expect PASS)
#   APP_DIR=~/devsecops ./gate.sh      # gate the flawed sample app (expect FAIL)
#
# Output: out/reports/*.json (+ SARIF for GitHub code scanning) and out/site/index.html.
# Exit code: 0 when the gate passes, 1 when it fails.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
APP_DIR="$(cd "${APP_DIR:-$ROOT/01-image-hardening/hardened}" && pwd)"
IMAGE="${IMAGE:-kbx-gate/$(basename "$APP_DIR"):ci}"
OUT="${OUT:-$HERE/out}"
GITLEAKS_CONFIG="${GITLEAKS_CONFIG:-$ROOT/02-secret-leak-response/.gitleaks.toml}"
K8S_DIR="${K8S_DIR:-$ROOT/05-k8s-admission-kind/manifests/allowed}"
export PATH="$HOME/.venvs/devsecops/bin:$PATH"

R="$OUT/reports"
rm -rf "$OUT" && mkdir -p "$R" "$OUT/site"
step() { printf '\033[1;36m--> %s\033[0m\n' "$*"; }

# 1. Secrets: the whole git history when the app lives in a repo, otherwise just the files.
if top="$(git -C "$APP_DIR" rev-parse --show-toplevel 2>/dev/null)"; then
  step "gitleaks git $top (full history)"
  gitleaks git --no-banner --redact --config "$GITLEAKS_CONFIG" --exit-code 0 \
    --report-format json --report-path "$R/gitleaks.json" "$top" >/dev/null 2>&1
else
  step "gitleaks dir $APP_DIR"
  gitleaks dir --no-banner --redact --config "$GITLEAKS_CONFIG" --exit-code 0 \
    --report-format json --report-path "$R/gitleaks.json" "$APP_DIR" >/dev/null 2>&1
fi
gitleaks dir --no-banner --redact --config "$GITLEAKS_CONFIG" --exit-code 0 \
  --report-format sarif --report-path "$R/gitleaks.sarif" "$APP_DIR" >/dev/null 2>&1

# 2. Dockerfile lint.
step "hadolint $APP_DIR/Dockerfile"
hadolint --no-fail -f json "$APP_DIR/Dockerfile" > "$R/hadolint.json"
hadolint --no-fail -f sarif "$APP_DIR/Dockerfile" > "$R/hadolint.sarif"

# 3. SAST on the application code.
step "semgrep (p/python, p/dockerfile)"
semgrep scan --config p/python --config p/dockerfile --metrics off --quiet \
  --json-output "$R/semgrep.json" --sarif-output "$R/semgrep.sarif" "$APP_DIR" >/dev/null

step "bandit"
bandit -q -r "$APP_DIR" -f json -o "$R/bandit.json" || true

# 4. Policy-as-code for the Dockerfile and the Kubernetes manifests that deploy it.
step "checkov (dockerfile$( [[ -d "$K8S_DIR" ]] && echo ', kubernetes'))"
ck_args=(-d "$APP_DIR" --framework dockerfile)
[[ -d "$K8S_DIR" ]] && ck_args=(-d "$APP_DIR" -d "$K8S_DIR" --framework dockerfile kubernetes)
checkov "${ck_args[@]}" --quiet --compact -o json > "$R/checkov.json" 2>/dev/null || true

# 5. Build the image and scan what will actually ship.
step "docker build -t $IMAGE"
docker build -q -t "$IMAGE" "$APP_DIR" >/dev/null
docker image inspect "$IMAGE" > "$R/inspect.json"

step "trivy image $IMAGE"
trivy image --quiet --scanners vuln,secret --format json --output "$R/trivy.json" "$IMAGE"
trivy convert --format sarif --output "$R/trivy.sarif" "$R/trivy.json"

step "grype $IMAGE"
grype --quiet -o json "docker:$IMAGE" > "$R/grype.json"

step "dockle $IMAGE"
ignores=()   # reviewed exceptions, one code per line in <app>/.dockleignore
if [[ -f "$APP_DIR/.dockleignore" ]]; then
  while read -r code; do ignores+=(--ignore "$code"); done < <(grep -oE '^[A-Z]+-[A-Z]+-[0-9]+' "$APP_DIR/.dockleignore")
fi
dockle "${ignores[@]}" --format json --output "$R/dockle.json" "$IMAGE" >/dev/null || true

step "syft $IMAGE (SBOM)"
syft --quiet "docker:$IMAGE" -o "cyclonedx-json=$R/sbom.cdx.json"

# 6. Decide.
echo
set +e
python3 "$HERE/gate.py" "$R" --policy "$HERE/policy.env" --html "$OUT/site/index.html" \
  --title "Security gate: $(basename "$APP_DIR")"
rc=$?
set -e
exit "$rc"
