#!/usr/bin/env bash
# Run every project in order and print one line per project.
#
#   ./run-all.sh            # about 15 minutes on a 2 vCPU KodeBox (after setup/)
#   ./run-all.sh 03 05      # only some projects (03 must have run before 05)
#
# Full logs: ~/kbx-logs/<step>.log
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS="${LOGS:-$HOME/kbx-logs}"
mkdir -p "$LOGS"
cd "$ROOT"

steps=(
  "01|Image hardening (before/after scan)|./01-image-hardening/compare.sh"
  "02|Secret leak response (10 checks)|./02-secret-leak-response/run-lab.sh"
  "03|SBOM, signing, attestations (6 checks)|./03-sbom-and-signing/pipeline.sh"
  "04|CI gate: hardened app must PASS|./04-ci-security-gate/gate.sh"
  "04|CI gate: flawed app must FAIL|! APP_DIR=$HOME/devsecops OUT=/tmp/gate-legacy ./04-ci-security-gate/gate.sh"
  "05|Kubernetes admission (deploy + 7 denials)|./05-k8s-admission-kind/run-lab.sh"
  "06|Falco runtime detection (6 rules)|./06-falco-runtime/falco-up.sh && ./06-falco-runtime/simulate.sh"
)

want=("$@")
results=()
for s in "${steps[@]}"; do
  IFS='|' read -r id title cmd <<<"$s"
  if [[ ${#want[@]} -gt 0 && ! " ${want[*]} " == *" $id "* ]]; then continue; fi
  log="$LOGS/${id}-$(echo "$title" | tr -cs 'A-Za-z0-9' '-' | cut -c1-30).log"
  printf '\033[1;36m==> %s %s\033[0m\n' "$id" "$title"
  start=$(date +%s)
  if bash -c "$cmd" >"$log" 2>&1; then status=PASS; else status=FAIL; fi
  secs=$(( $(date +%s) - start ))
  results+=("$(printf '%-6s %-3s %-45s %4ss  %s' "$status" "$id" "$title" "$secs" "$log")")
done

printf '\n\033[1m%-6s %-3s %-45s %5s  %s\033[0m\n' RESULT ID STEP TIME LOG
printf '%s\n' "${results[@]}"
! printf '%s\n' "${results[@]}" | grep -q '^FAIL'
