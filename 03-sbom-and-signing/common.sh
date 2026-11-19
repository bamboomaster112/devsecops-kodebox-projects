# Shared settings for projects 03 and 05 (sourced, not run).
REGISTRY_NAME="${REGISTRY_NAME:-kbx-registry}"
REGISTRY_HOST="${REGISTRY_HOST:-localhost:5000}"      # how the box reaches the registry
REGISTRY_IMAGE="${REGISTRY_IMAGE:-registry:3}"
KEY_DIR="${KEY_DIR:-$HOME/.kbx/cosign}"               # outside the repo, never committed
TLS_DIR="${TLS_DIR:-$HOME/.kbx/registry-tls}"         # lab CA and registry certificate
REGISTRY_CA="$TLS_DIR/ca.crt"
VULN_PREDICATE_TYPE="https://github.com/bamboomaster112/devsecops-kodebox-projects/vuln-summary/v1"

step() { printf '\033[1;36m--> %s\033[0m\n' "$*"; }

# Go tools (cosign, syft, grype, kubectl) honour SSL_CERT_FILE. Point it at the system
# CAs plus the lab CA, so they trust the registry and still reach the internet.
use_lab_ca() {
  [[ -f "$TLS_DIR/ca-bundle.pem" ]] && export SSL_CERT_FILE="$TLS_DIR/ca-bundle.pem"
  return 0
}

# A private registry with its own CA, the way most companies run one. The certificate
# covers both names the registry is reached by: localhost (from the box) and
# kbx-registry (from inside the kind cluster in project 05).
ensure_registry_tls() {
  [[ -f "$TLS_DIR/registry.crt" ]] && { use_lab_ca; return 0; }
  step "Creating a lab CA and a TLS certificate for the registry in $TLS_DIR"
  mkdir -p "$TLS_DIR" && chmod 700 "$TLS_DIR"
  openssl req -x509 -newkey rsa:3072 -nodes -days 365 -subj "/CN=KodeBox Lab Registry CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" 2>/dev/null
  openssl req -newkey rsa:3072 -nodes -subj "/CN=kbx-registry" \
    -keyout "$TLS_DIR/registry.key" -out "$TLS_DIR/registry.csr" 2>/dev/null
  printf '%s\n' "subjectAltName=DNS:kbx-registry,DNS:localhost,IP:127.0.0.1" \
    "extendedKeyUsage=serverAuth" "basicConstraints=CA:FALSE" "keyUsage=digitalSignature,keyEncipherment" \
    > "$TLS_DIR/registry.ext"
  openssl x509 -req -in "$TLS_DIR/registry.csr" -CA "$TLS_DIR/ca.crt" -CAkey "$TLS_DIR/ca.key" \
    -CAcreateserial -days 365 -extfile "$TLS_DIR/registry.ext" -out "$TLS_DIR/registry.crt" 2>/dev/null
  chmod 600 "$TLS_DIR/ca.key"
  chmod 644 "$TLS_DIR/registry.key"   # read by the registry container; the registry only listens on 127.0.0.1
  cat /etc/ssl/certs/ca-certificates.crt "$TLS_DIR/ca.crt" > "$TLS_DIR/ca-bundle.pem"
  use_lab_ca
}
use_lab_ca

# Cosign key pair for the lab. The private key is encrypted with a random password
# kept next to it (mode 600). In production use a KMS key or keyless signing instead.
ensure_keys() {
  mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
  if [[ ! -f "$KEY_DIR/cosign.key" ]]; then
    step "Generating a cosign key pair in $KEY_DIR"
    (umask 077; python3 -c 'import secrets; print(secrets.token_urlsafe(24))' > "$KEY_DIR/password")
    COSIGN_PASSWORD="$(cat "$KEY_DIR/password")" \
      cosign generate-key-pair --output-key-prefix "$KEY_DIR/cosign" >/dev/null 2>&1
  fi
  # Cosign 3 signs through a "signing config" that lists the Sigstore services to use.
  # An empty one means: key-based signing, nothing sent to the public transparency log
  # or timestamp authority. Verifiers then need --insecure-ignore-tlog=true.
  if [[ ! -f "$KEY_DIR/signing-config.json" ]]; then
    cosign signing-config create --out "$KEY_DIR/signing-config.json" >/dev/null
  fi
  SIGNING_CONFIG="$KEY_DIR/signing-config.json"
  export COSIGN_PASSWORD
  COSIGN_PASSWORD="$(cat "$KEY_DIR/password")"
  COSIGN_KEY="$KEY_DIR/cosign.key"
  COSIGN_PUB="$KEY_DIR/cosign.pub"
}

# Resolve a pushed tag (localhost:5000/repo:tag) to an immutable repo@sha256 reference
# by asking the registry for the manifest digest, exactly what a deploy tool would do.
digest_ref() {
  local tagged="$1"
  local repo="${tagged%:*}" tag="${tagged##*:}"
  local host="${repo%%/*}" path="${repo#*/}"
  local digest
  digest="$(curl -fsSI --cacert "$REGISTRY_CA" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "https://${host}/v2/${path}/manifests/${tag}" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}')"
  [[ -n "$digest" ]] || { echo "could not resolve $tagged" >&2; return 1; }
  echo "${repo}@${digest}"
}
