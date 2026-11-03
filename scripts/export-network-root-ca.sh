#!/usr/bin/env bash
# Exports the CA certificates your network uses to re-sign HTTPS traffic (for example Cisco Secure
# Access / Umbrella, Zscaler) to certs/network-root-ca.pem, so the container can trust them.
# macOS and Linux. Uses the system's openssl and (on macOS) the keychains; changes no settings.
#
# Usage:  bash scripts/export-network-root-ca.sh [--host api.openai.com] [--skip-if-public]
#
# It writes the root CA and long-lived intermediates - never the site's own certificate, and not
# short-lived intermediates (they rotate and are sent by the network on every connection anyway).
# Confirm with your IT/security team that the exported certificates are your organisation's
# expected inspection CAs before trusting them.
set -euo pipefail

HOST="api.openai.com"
PORT=443
SKIP_IF_PUBLIC=0
MIN_INTERMEDIATE_DAYS=90
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT_DIR/certs/network-root-ca.pem"
PUBLIC_ISSUERS="DigiCert|GlobalSign|Google Trust|Let's Encrypt|ISRG|Sectigo|Baltimore|Amazon|Microsoft|Entrust|GoDaddy|Starfield|Comodo|USERTrust|Cloudflare"

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --skip-if-public) SKIP_IF_PUBLIC=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null || { echo "openssl is required but was not found." >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

subject() { openssl x509 -noout -subject -nameopt RFC2253 -in "$1" | sed 's/^subject= *//'; }
issuer()  { openssl x509 -noout -issuer  -nameopt RFC2253 -in "$1" | sed 's/^issuer= *//'; }
enddate() { openssl x509 -noout -enddate -in "$1" | sed 's/^notAfter=//'; }
sha256()  { openssl x509 -noout -fingerprint -sha256 -in "$1" | sed 's/^.*=//; s/://g'; }
is_ca()   { openssl x509 -noout -text -in "$1" | grep -A1 "Basic Constraints" | grep -q "CA:TRUE"; }
is_root() { [ "$(subject "$1")" = "$(issuer "$1")" ]; }
# Succeeds if the certificate is still valid N days from now.
valid_for_days() { openssl x509 -noout -checkend $(( $2 * 86400 )) -in "$1" >/dev/null 2>&1; }

# Split a PEM bundle into one file per certificate: split_pem <bundle> <prefix>
split_pem() {
  awk -v prefix="$2" '
    /-----BEGIN CERTIFICATE-----/ { n++; out = sprintf("%s-%03d.pem", prefix, n) }
    out { print > out }
    /-----END CERTIFICATE-----/ { close(out); out = "" }
  ' "$1"
}

# 1. Capture the chain the server (or inspection proxy) presents.
PROXY="${HTTPS_PROXY:-${https_proxy:-}}"
P="${PROXY#*://}"; P="${P%%/*}"; P="${P##*@}"
fetch_chain() {  # fetch_chain [proxy-args...]  (bash 3.2-safe: no empty-array expansion)
  openssl s_client -connect "$HOST:$PORT" -servername "$HOST" -showcerts "$@" \
    </dev/null >"$WORK/handshake.txt" 2>/dev/null || true
  grep -q "BEGIN CERTIFICATE" "$WORK/handshake.txt"
}
got=1
if [ -n "$PROXY" ]; then
  fetch_chain -proxy "$P" || fetch_chain || got=0   # retry directly if this openssl lacks -proxy
else
  fetch_chain || got=0
fi
if [ "$got" = 0 ]; then
  echo "Could not open a TLS connection to $HOST:$PORT (check network/VPN)." >&2
  exit 1
fi
split_pem "$WORK/handshake.txt" "$WORK/sent"
LEAF="$WORK/sent-001.pem"
[ -f "$LEAF" ] || { echo "No certificate was received from $HOST." >&2; exit 1; }

echo "Site certificate presented for $HOST: $(subject "$LEAF")"
echo "  issued by: $(issuer "$LEAF")"

if [ "$SKIP_IF_PUBLIC" = 1 ] && issuer "$LEAF" | grep -Eq "$PUBLIC_ISSUERS"; then
  echo "This looks like a publicly issued certificate, so your network is not inspecting this traffic."
  echo "No extra CA certificates are needed. Nothing was written."
  exit 0
fi

# 2. CA certificates sent in the handshake (excluding the leaf).
CAS=()
add_ca() {
  local f="$1" s existing
  is_ca "$f" || return 0
  s="$(sha256 "$f")"
  for existing in "${CAS[@]:-}"; do
    [ -n "$existing" ] && [ "$(sha256 "$existing")" = "$s" ] && return 0
  done
  CAS+=("$f")
}
for f in "$WORK"/sent-*.pem; do
  [ "$f" = "$LEAF" ] && continue
  add_ca "$f"
done

# 3. Walk issuers through the system trust stores until a self-signed root is found.
build_candidates() {
  : >"$WORK/system.pem"
  if [ "$(uname)" = "Darwin" ]; then
    for kc in /Library/Keychains/System.keychain \
              /System/Library/Keychains/SystemRootCertificates.keychain \
              "$HOME/Library/Keychains/login.keychain-db"; do
      [ -f "$kc" ] && security find-certificate -a -p "$kc" >>"$WORK/system.pem" 2>/dev/null || true
    done
  else
    for b in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
      [ -f "$b" ] && cat "$b" >>"$WORK/system.pem"
    done
  fi
  split_pem "$WORK/system.pem" "$WORK/sys"
}
find_by_subject() {
  local want="$1" f
  for f in "$WORK"/sys-*.pem; do
    [ -f "$f" ] || continue
    [ "$(subject "$f")" = "$want" ] && { echo "$f"; return 0; }
  done
  return 1
}

current="$LEAF"
if [ "${#CAS[@]}" -gt 0 ]; then current="${CAS[${#CAS[@]}-1]}"; fi
if ! is_root "$current"; then
  echo "Looking up the issuing CA in the system trust store..."
  build_candidates
  for _ in 1 2 3 4 5; do
    is_root "$current" && break
    found="$(find_by_subject "$(issuer "$current")" || true)"
    [ -n "$found" ] || break
    add_ca "$found"
    current="$found"
  done
fi

if [ "${#CAS[@]}" -eq 0 ]; then
  echo ""
  echo "Could not find the issuing CA certificates for this site." >&2
  echo "Ask IT for your network's inspection root CA (PEM) and save it in the certs folder." >&2
  exit 1
fi

# 4. Keep roots and long-lived intermediates.
have_root=0
for f in "${CAS[@]}"; do is_root "$f" && have_root=1; done
mkdir -p "$(dirname "$OUT")"
: >"$WORK/out.pem"
echo ""
for f in "${CAS[@]}"; do
  if is_root "$f"; then kind="root"; else kind="intermediate"; fi
  if [ "$kind" = "intermediate" ] && [ "$have_root" = 1 ] && ! valid_for_days "$f" "$MIN_INTERMEDIATE_DAYS"; then
    echo " - skipped [$kind, expires $(enddate "$f")] $(subject "$f")"
    continue
  fi
  echo " - [$kind] $(subject "$f")"
  echo "   SHA-256: $(sha256 "$f")  expires: $(enddate "$f")"
  {
    echo "# Subject: $(subject "$f")"
    echo "# Issuer:  $(issuer "$f")"
    openssl x509 -in "$f"
    echo ""
  } >>"$WORK/out.pem"
done
[ "$have_root" = 1 ] || echo "Note: no self-signed root was found; the intermediates alone are usually sufficient."
mv "$WORK/out.pem" "$OUT"
echo ""
echo "CA certificates written to $OUT (confirm these with IT)."
