#!/usr/bin/env bash
# Print every tool the projects use, its version, and the box's spare capacity.
set -uo pipefail
export PATH="$HOME/.venvs/devsecops/bin:$PATH"

ver() {  # ver <name> <command...>  -> prints the first version-looking string
  local name="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    printf '  %-16s %s\n' "$name" "$(grep -oE 'v?[0-9]+\.[0-9]+(\.[0-9]+)?' <<<"$out" | head -1)"
  else
    printf '  %-16s %s\n' "$name" "MISSING"
  fi
}

echo "Toolkit (preinstalled on the KodeBox)"
ver docker      docker --version
ver trivy       trivy --version
ver grype       grype version
ver syft        syft version
ver cosign      cosign version
ver hadolint    hadolint --version
ver gitleaks    gitleaks version
ver dockle      dockle --version

echo "Extras (setup/install-extras.sh)"
ver kubectl     kubectl version --client
ver kind        kind version
ver helm        helm version --short
ver pre-commit  pre-commit --version
ver semgrep     semgrep --version
ver checkov     checkov --version
ver bandit      bandit --version
ver git-filter-repo bash -c "pip show git-filter-repo 2>/dev/null | grep Version"

echo "Capacity"
printf '  %-16s %s\n' "vCPU" "$(nproc)"
printf '  %-16s %s\n' "memory free" "$(free -h | awk '/^Mem/ {print $7}')"
printf '  %-16s %s\n' "disk free (/)" "$(df -h / | awk 'NR==2 {print $4}')"
printf '  %-16s %s\n' "containers" "$(docker ps -q | wc -l) running"
