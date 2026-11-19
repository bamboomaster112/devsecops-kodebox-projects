#!/usr/bin/env bash
# Apply the Kyverno policies, filling the cosign public key from project 03.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
source "$ROOT/03-sbom-and-signing/common.sh"
PUB="$KEY_DIR/cosign.pub"
[[ -f "$PUB" ]] || { echo "No $PUB: run 03-sbom-and-signing/pipeline.sh first" >&2; exit 1; }

kubectl apply -f "$HERE/policies/"   # picks up *.yaml only; the .tpl is rendered below
# Indent the PEM to sit under 'publicKeys: |-' in the template.
python3 - "$HERE/policies/verify-image-signature.yaml.tpl" "$PUB" <<'PY' | kubectl apply -f -
import re, sys
tpl, pub = open(sys.argv[1]).read(), open(sys.argv[2]).read().strip().splitlines()
def fill(m):
    indent = m.group(1)
    return "\n".join(indent + line for line in pub)
print(re.sub(r"^( *)__COSIGN_PUBLIC_KEY__$", fill, tpl, flags=re.M))
PY
kubectl get validatingpolicies,imagevalidatingpolicies
