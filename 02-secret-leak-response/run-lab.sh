#!/usr/bin/env bash
# Project 02: respond to a leaked secret, end to end.
#
#   ./run-lab.sh            # run every stage and print a PASS/FAIL summary
#   ./run-lab.sh --pause    # stop after each stage so you can look around
#
# Works on a throwaway clone of ~/devsecops in ~/work/leak-lab, so the original
# sample repo is never changed. The leaked value is the toolkit's FAKE token.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SAMPLE_APP_DIR:-$HOME/devsecops}"
WORK="${WORK:-$HOME/work/leak-lab}"
R="$WORK/reports"
PAUSE=false
[[ "${1:-}" == "--pause" ]] && PAUSE=true
export PATH="$HOME/.venvs/devsecops/bin:$PATH"

declare -a RESULTS=()
stage() { printf '\n\033[1;35m=== Stage %s ===\033[0m\n' "$*"; }
say()   { printf '\033[1;36m--> %s\033[0m\n' "$*"; }
check() {  # check <label> <expected> <actual>
  local status=PASS
  [[ "$2" == "$3" ]] || status=FAIL
  RESULTS+=("$status|$1|expected $2, got $3")
  printf '    [%s] %s (expected %s, got %s)\n' "$status" "$1" "$2" "$3"
}
pause() { $PAUSE && read -r -p "    Press Enter for the next stage..." _ || true; }
leaks() {  # leaks <mode git|dir> <report-name> [extra gitleaks flags...] -> prints finding count
  local mode="$1" name="$2"; shift 2
  gitleaks "$mode" --no-banner --redact --report-format json --report-path "$R/$name.json" "$@" . >/dev/null 2>&1 || true
  jq length "$R/$name.json"
}
gt0() { [[ "$1" -gt 0 ]] && echo yes || echo no; }

for bin in git gitleaks jq pre-commit git-filter-repo; do
  command -v "$bin" >/dev/null || { echo "missing $bin (run setup/install-extras.sh)" >&2; exit 1; }
done

rm -rf "$WORK" && mkdir -p "$R"
git clone -q "$SRC" "$WORK/app"
cd "$WORK/app"
git config user.name "KodeBox Lab"
git config user.email "lab@kodebox.invalid"

# ---------------------------------------------------------------------------
stage "1: Detect - scan the files and the full git history"
n_hist="$(leaks git 1-history)"
n_dir="$(leaks dir 1-files)"
jq -r '.[] | "    \(.RuleID)  \(.File):\(.StartLine)  commit \(.Commit[0:8])  secret \(.Secret)"' "$R/1-history.json"
check "leak found in git history" yes "$(gt0 "$n_hist")"
check "leak found in working tree" yes "$(gt0 "$n_dir")"
pause

# ---------------------------------------------------------------------------
stage "2: Contain - remove the token from the code and load it from the environment"
printf 'APP_ENV=development\n# Set GITHUB_TOKEN in the environment or a secret manager, never in git.\nGITHUB_TOKEN=\n' > config.env.example
git rm -q config.env
printf 'config.env\n*.env\n!*.env.example\n' >> .gitignore
git add .gitignore config.env.example
git commit -q -m "Remove hard-coded token; read it from the environment"
check "working tree clean after the fix" 0 "$(leaks dir 2-files)"
n_hist2="$(leaks git 2-history)"
say "History still holds the token: deleting a file does not delete it from earlier commits."
check "token still in history after the fix" yes "$(gt0 "$n_hist2")"
pause

# ---------------------------------------------------------------------------
stage "3: Rotate - treat the token as compromised"
cat <<'EOF'
    The moment a secret reaches a shared repo, assume someone copied it. In order:
      1. Revoke it at the provider (GitHub: Settings > Developer settings > Personal access tokens).
      2. Issue a replacement with the smallest scope and shortest expiry that works.
      3. Store the new one in a secret manager or CI secret, and inject it at runtime.
      4. Check the provider's audit log for use of the old token since the leak commit.
    (The token here is fake, so there is nothing to revoke in this lab.)
EOF
check "rotation checklist reviewed" yes yes
pause

# ---------------------------------------------------------------------------
stage "4: Purge - rewrite history so the token is gone from every commit"
old_head="$(git rev-parse --short HEAD)"
echo 'regex:ghp_[0-9A-Za-z]{36}==>REDACTED_GITHUB_TOKEN' > "$R/replacements.txt"
git filter-repo --force --quiet --replace-text "$R/replacements.txt"
new_head="$(git rev-parse --short HEAD)"
say "HEAD was $old_head, now $new_head: every commit after the leak has a new hash."
git log --all -p --format='    %h %s' -- config.env | grep -E '^    [0-9a-f]{7}|GITHUB_TOKEN' | sed 's/^+/    +/'
check "history clean after filter-repo" 0 "$(leaks git 4-history)"
cat <<'EOF'
    On a real remote you would now: force-push every branch and tag, ask everyone to
    re-clone, and ask the host to purge cached views and pull-request refs.
    Rotation (stage 3) still matters: forks and clones made before the purge keep the token.
EOF
pause

# ---------------------------------------------------------------------------
stage "5: Prevent - block secrets before they are committed"
cp "$HERE/.gitleaks.toml" .gitleaks.toml
cp "$HERE/pre-commit-config.yaml" .pre-commit-config.yaml
git add .gitleaks.toml .pre-commit-config.yaml
git commit -q -m "Add gitleaks config and pre-commit hooks"
pre-commit install >/dev/null
say "pre-commit hook installed: $(ls .git/hooks/pre-commit)"

fake_key="kbx_$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
echo "INTERNAL_API_KEY=${fake_key}" > service.cfg
git add service.cfg
set +e
git commit -m "Add service settings" > "$R/5-blocked-commit.txt" 2>&1
rc=$?
set -e
grep -E 'RuleID|Finding|leaks found|Failed' "$R/5-blocked-commit.txt" | sed 's/^/    /' || true
check "commit with an internal key is blocked" blocked "$([[ $rc -ne 0 ]] && echo blocked || echo allowed)"
git reset -q HEAD service.cfg && rm -f service.cfg

echo "Notes for the team." > NOTES.md
git add NOTES.md
set +e
git commit -q -m "Add notes" > "$R/5-clean-commit.txt" 2>&1
rc=$?
set -e
check "clean commit is allowed" allowed "$([[ $rc -eq 0 ]] && echo allowed || echo blocked)"
pause

# ---------------------------------------------------------------------------
stage "6: Baseline - adopt scanning on a repo whose history you cannot rewrite"
git clone -q "$SRC" "$WORK/legacy"
cd "$WORK/legacy"
git config user.name "KodeBox Lab"
git config user.email "lab@kodebox.invalid"
n_base="$(leaks git 6-baseline --config "$HERE/.gitleaks.toml")"
say "Baseline records $n_base known finding(s); they are tracked, not re-reported."

echo "INTERNAL_API_KEY=kbx_$(python3 -c 'import secrets; print(secrets.token_hex(16))')" > new-service.cfg
git add new-service.cfg && git commit -q --no-verify -m "Add new service settings"
n_new="$(leaks git 6-new --config "$HERE/.gitleaks.toml" --baseline-path "$R/6-baseline.json")"
jq -r '.[] | "    NEW: \(.RuleID)  \(.File):\(.StartLine)  fingerprint \(.Fingerprint)"' "$R/6-new.json"
check "only the new leak is reported against the baseline" yes \
  "$([[ "$n_new" -ge 1 ]] && ! jq -e '.[] | select(.File == "config.env")' "$R/6-new.json" >/dev/null && echo yes || echo no)"

jq -r '.[].Fingerprint' "$R/6-new.json" > .gitleaksignore
check "accepted finding silenced by .gitleaksignore" 0 \
  "$(leaks git 6-ignored --config "$HERE/.gitleaks.toml" --baseline-path "$R/6-baseline.json")"
say "Use .gitleaksignore only after the secret is rotated: ignoring a live key hides the risk."

# ---------------------------------------------------------------------------
printf '\n\033[1m%-6s %-52s %s\033[0m\n' RESULT CHECK DETAIL
fails=0
for r in "${RESULTS[@]}"; do
  IFS='|' read -r s label detail <<<"$r"
  printf '%-6s %-52s %s\n' "$s" "$label" "$detail"
  [[ "$s" == PASS ]] || fails=$((fails + 1))
done
echo "Reports: $R"
exit "$fails"
