#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# SONiC Attestation: Quote Verifier
# - Verifies the quote signature against the AK public key
# - Checks the nonce consistency
#
# Requires: tpm2-tools
#
# Usage:
#   ./verify_quote.sh <QUOTE_DIR> [AK_PUB]
#     QUOTE_DIR: directory created by generate_quote.sh
#     AK_PUB   : optional path to AK public key (defaults to meta or /var/lib/sonic/attestation/ak.pub)
# ============================================================

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

: "${DEFAULT_AK_PUB:=/var/lib/sonic/attestation/ak.pub}"
: "${HASH_ALG:=sha256}"   # must match what was used to quote

command -v tpm2_checkquote >/dev/null 2>&1 || { echo "Missing tpm2-tools"; exit 1; }

if [ $# -lt 1 ]; then
  echo "Usage: $0 <QUOTE_DIR> [AK_PUB]"
  exit 1
fi

QUOTE_DIR="$1"
[ -d "$QUOTE_DIR" ] || { echo "Not a directory: $QUOTE_DIR"; exit 1; }

# Resolve AK public key path
AK_PUB_ARG="${2:-}"

# Try to read meta if present to determine AK pub path
META="${QUOTE_DIR}/quote_meta.json"
if [ -z "$AK_PUB_ARG" ] && [ -f "$META" ]; then
  # shellcheck disable=SC2002
  AK_PUB_ARG="$(cat "$META" | sed -n 's/.*"ak_pub_file": *"\([^"]*\)".*/\1/p' | head -n1 || true)"
fi
AK_PUB="${AK_PUB_ARG:-$DEFAULT_AK_PUB}"

[ -s "$AK_PUB" ] || { echo "AK public key not found: $AK_PUB"; exit 1; }

ATTEST="${QUOTE_DIR}/quote.attest"
SIG="${QUOTE_DIR}/quote.sig"
PCRMAP="${QUOTE_DIR}/pcrs.bin"
NONCE_HEX_FILE="${QUOTE_DIR}/nonce.hex"

for f in "$ATTEST" "$SIG" "$PCRMAP" "$NONCE_HEX_FILE"; do
  [ -s "$f" ] || { echo "Missing required file: $f"; exit 1; }
done

NONCE_HEX="$(tr -d '\n\r ' < "$NONCE_HEX_FILE")"
[ -n "$NONCE_HEX" ] || { echo "Nonce file is empty"; exit 1; }

OUT="${QUOTE_DIR}/verification.txt"

log "Verifying quote signature…"
if tpm2_checkquote \
  -u "$AK_PUB" \
  -g "$HASH_ALG" \
  -m "$ATTEST" \
  -s "$SIG" \
  -f "$PCRMAP" \
  -q "$NONCE_HEX" \
  > "$OUT"; then
    log "Quote verification: SUCCESS"
else
    log "Quote verification: FAILED"
    echo "Verification failed. See $OUT for details."
    exit 1
fi

log "Verification complete."
echo "Result saved to: $OUT"
echo
echo "==== tpm2_checkquote output ===="
cat "$OUT"
