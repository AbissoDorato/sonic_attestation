#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# SONiC Attestation - Quote Verifier (format tolerant)
#
# Usage:
#   ./verify_attestation.sh <ARTIFACT_DIR>
#
# Expected inputs inside ARTIFACT_DIR (any mix is ok):
#   - quote.msg          # TPMS_ATTEST structure (preferred)
#   - OR: quote.attest   # same content, older filename
#   - quote.sig          # signature over the attestation
#   - nonce.hex          # hex-encoded nonce used in the quote
#   - ak.pub (optional)  # AK public key in PEM; can also come from $AK_PUB
#
# Behavior:
#   - Picks AK from $AK_PUB, or ARTIFACT_DIR/ak.pub, or /var/lib/sonic/attestation/ak.pub
#   - Verifies quote with tpm2_checkquote
#   - Writes normalized PCR map to ARTIFACT_DIR/pcrs.yaml if not present
#   - Prints clear PASS/FAIL messages and exits accordingly
# ------------------------------------------------------------

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# --- args ---
ARTDIR="${1:-}"
[[ -n "$ARTDIR" ]] || die "Usage: $0 <ARTIFACT_DIR>"
[[ -d "$ARTDIR" ]] || die "Not a directory: $ARTDIR"

# --- locate files (tolerate names) ---
ATTEST=""
for cand in "quote.msg" "quote.attest" "attest.bin" "pcrs.bin"; do
  if [[ -s "$ARTDIR/$cand" ]]; then ATTEST="$ARTDIR/$cand"; break; fi
done
[[ -n "$ATTEST" ]] || die "Missing required file: quote.msg (or quote.attest) in $ARTDIR"

SIG="$ARTDIR/quote.sig"
[[ -s "$SIG" ]] || die "Missing required file: $SIG"

NONCE_FILE="$ARTDIR/nonce.hex"
[[ -s "$NONCE_FILE" ]] || die "Missing required file: $NONCE_FILE"

NONCE_HEX="$(tr -d ' \n\r\t' < "$NONCE_FILE" | tr '[:upper:]' '[:lower:]')"
[[ "$NONCE_HEX" =~ ^[0-9a-f]+$ ]] || die "nonce.hex is not valid hex"

# --- find AK public key ---
if [[ -n "${AK_PUB:-}" ]]; then
  AK="$AK_PUB"
elif [[ -s "$ARTDIR/ak.pub" ]]; then
  AK="$ARTDIR/ak.pub"
elif [[ -s "/var/lib/sonic/attestation/ak.pub" ]]; then
  AK="/var/lib/sonic/attestation/ak.pub"
else
  die "AK public key not found. Provide with AK_PUB env or place ak.pub in $ARTDIR"
fi
[[ -s "$AK" ]] || die "AK public key file not readable: $AK"

# --- Optional: choose output PCR YAML (create if missing) ---
PCR_YAML="$ARTDIR/pcrs.yaml"
NEED_PCR_OUT="0"
if [[ ! -s "$PCR_YAML" ]]; then
  PCR_YAML="$(mktemp --tmpdir="$ARTDIR" pcrs.XXXX.yaml)"
  NEED_PCR_OUT="1"
fi

# --- Determine signature format (default: plain RSASSA) ---
# If you’re using ECC AK, set SIGFMT=ecdsa via env; otherwise plain works for RSA AKs.
echo "Determining signature format..."
PCRS_BIN="$ARTDIR/pcrs.bin"
if [[ -r "$PCRS_BIN" ]]; then
  # do whatever parsing you need here (e.g., stash/copy it)
  cp -f "$PCRS_BIN" "$ARTDIR/pcrs.bin.copy"
fi


# --- Hash alg for the quote (must match the AK/quote; default sha256) ---
HALG="${HALG:-sha256}"

log "Verifying quote:"
log " - attest: $ATTEST"
log " - sig:    $SIG"
log " - ak:     $AK"
log " - nonce:  $NONCE_HEX"
log " - fmt:    $PCRS_BIN"
log " - halg:   $HALG"

# tpm2_checkquote returns non-zero on failure. We also capture output for logs.
set +e
OUT="$(
  tpm2_checkquote \
    -u "$AK" \
    -m "$ATTEST" \
    -s "$SIG" \
    -f "$PCRS_BIN" \
    -g "$HALG" \
    -q "$NONCE_HEX" \
)"
RC=$?
set -e

echo "$OUT"

if (( RC != 0 )); then
  # Make the error crystal clear for the caller (verifier.py)
  echo "FAIL: tpm2_checkquote failed with code $RC" >&2
  exit $RC
fi

# If we created a temp PCR file, normalize its name to pcrs.yaml for the verifier.
if [[ "$NEED_PCR_OUT" == "1" ]]; then
  mv -f "$PCR_YAML" "$ARTDIR/pcrs.yaml"
  PCR_YAML="$ARTDIR/pcrread.txt"
fi

# Optional: sanity check that PCR YAML is non-empty
if [[ ! -s "$PCR_YAML" ]]; then
  die "Verification succeeded but PCR output is missing/empty"
fi

echo "PASS"

