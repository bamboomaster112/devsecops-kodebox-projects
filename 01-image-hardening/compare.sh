#!/usr/bin/env bash
# Scan the flawed sample app (~/devsecops) and the hardened version side by side.
#
#   ./compare.sh                    # before = ~/devsecops, after = ./hardened
#   SAMPLE_APP_DIR=/path ./compare.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SAMPLE_APP_DIR="${SAMPLE_APP_DIR:-$HOME/devsecops}"
REPORTS="${REPORTS:-$HERE/reports}"

[[ -f "$SAMPLE_APP_DIR/Dockerfile" ]] || { echo "No Dockerfile in $SAMPLE_APP_DIR" >&2; exit 1; }

"$HERE/scan-image.sh" "$SAMPLE_APP_DIR"   sample-app:before "$REPORTS/before"
"$HERE/scan-image.sh" "$HERE/hardened"    sample-app:after  "$REPORTS/after"

echo
python3 "$ROOT/lib/kbx_reports.py" compare "$REPORTS/before" "$REPORTS/after"
echo
echo "Details: $REPORTS/{before,after}/  (hadolint.txt and trivy.txt are human-readable)"
