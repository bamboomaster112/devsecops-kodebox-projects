#!/usr/bin/env bash
# Send every manifest in manifests/denied to the API server (server-side dry run, so
# nothing is created) and check that admission rejects it for the expected reason.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf '\033[1m%-6s %-30s %-8s %s\033[0m\n' RESULT MANIFEST VERDICT "DECIDED BY"
fails=0
for f in "$HERE"/manifests/denied/*.yaml; do
  expected_by="$(sed -n 's/^# expect-denied-by: //p' "$f")"
  out="$(kubectl apply --dry-run=server -f "$f" 2>&1)"; rc=$?
  verdict=allowed; by="-"
  if [[ $rc -ne 0 ]]; then
    verdict=denied
    if grep -q 'violates PodSecurity' <<<"$out"; then
      by="Pod Security Admission"
    else
      # A request can trip several policies; list every one Kyverno names.
      pols="$(grep -oE 'restrict-image-registries|disallow-latest-tag|require-resource-limits|verify-image-signature' <<<"$out" | sort -u | paste -sd, -)"
      by="Kyverno ${pols:-?}"
    fi
  fi
  status=PASS
  exp_tool="${expected_by%% *}" exp_pol="${expected_by#Kyverno }"
  if [[ "$verdict" != denied ]]; then status=FAIL
  elif [[ "$exp_tool" == Kyverno ]]; then [[ "$by" == Kyverno*"$exp_pol"* ]] || status=FAIL
  else [[ "$by" == "$expected_by" ]] || status=FAIL; fi
  [[ $status == FAIL ]] && fails=$((fails + 1))
  printf '%-6s %-30s %-8s %s\n' "$status" "$(basename "$f")" "$verdict" "$by"
  if [[ $status == FAIL || "${VERBOSE:-}" == 1 ]]; then
    echo "       expected: $expected_by"
    echo "$out" | grep -vE '^\s*$' | head -6 | cut -c1-160 | sed 's/^/       /'
  fi
done
exit "$fails"
