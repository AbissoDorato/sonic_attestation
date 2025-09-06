#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# SONiC Attestation: Quote Generator
# - Creates a fresh nonce
# - Produces a TPM2 quote over selected PCRs
# - Saves artifacts into a timestamped directory
#
# Requires: tpm2-tools, openssl
#
# Usage:
#   ./generate_quote.sh [OUT_DIR_BASE]
#     OUT_DIR_BASE (optional) defaults to /var/lib/sonic/attestation/quotes
# ============================================================

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

# ---------------- Config / Defaults ----------------
: "${CONF:=/etc/sonic/attestation/attestation.conf}"
: "${STATE_DIR:=/var/lib/sonic/attestation}"
: "${OUT_BASE:=${1:-${STATE_DIR}/quotes}}"

# PCR bank + selection (example: "sha256:13,14,15")
: "${PCRS_SPEC:=sha256:13,14,15}"
# Hash/signature algorithm for the quote (should match the PCR bank)
: "${HASH_ALG:=sha256}"

# Attestation Key locations (choose one of these approaches):
# - AK by persistent handle (fast path on devices with provisioned AK)
: "${AK_HANDLE:=0x81010002}"
# - AK context file (if you load it dynamically elsewhere)
: "${AK_CTX:=${STATE_DIR}/ak.ctx}"
# AK public key file (needed later for verification)
: "${AK_PUB:=${STATE_DIR}/ak.pub}"

# Load optional overrides
[ -f "$CONF" ] && source "$CONF" || true

# ---------------- TPM Access Detection ----------------
detect_tcti() {
  if [ -e /dev/tpmrm0 ]; then echo "device:/dev/tpmrm0"; return; fi
  if [ -e /dev/tpm0   ]; then echo "device:/dev/tpm0";   return; fi
  # Allow a software TPM socket if explicitly present
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [ -S "$sock" ] && [ -S "${sock}.ctrl" ]; then echo "swtpm:path=${sock}"; return; fi
  echo ""
}

# ---------------- Pre-flight Checks ----------------
command -v tpm2_quote >/dev/null 2>&1 || { echo "Missing tpm2-tools"; exit 1; }
command -v tpm2_pcrread >/dev/null 2>&1 || { echo "Missing tpm2-tools"; exit 1; }
command -v tpm2_readpublic >/dev/null 2>&1 || true
command -v openssl >/dev/null 2>&1 || { echo "Missing openssl"; exit 1; }

TCTI="$(detect_tcti)"; [ -n "$TCTI" ] || { echo "No TPM available"; exit 1; }
export TPM2TOOLS_TCTI="$TCTI"

# Ensure AK public is present (if not, try to dump from handle/context)
ensure_ak_pub() {
  if [ -s "$AK_PUB" ]; then return; fi
  mkdir -p "$(dirname "$AK_PUB")"
  if [ -n "${AK_CTX:-}" ] && [ -f "$AK_CTX" ]; then
    log "AK public not found, exporting from AK context: $AK_CTX"
    tpm2_readpublic -c "$AK_CTX" -o "$AK_PUB" >/dev/null
  else
    log "AK public not found, exporting from AK handle: $AK_HANDLE"
    tpm2_readpublic -c "$AK_HANDLE" -o "$AK_PUB" >/dev/null
  fi
  [ -s "$AK_PUB" ] || { echo "Failed to obtain AK public key"; exit 1; }
}

main() {
  mkdir -p "$OUT_BASE"

  local ts outdir
  ts="$(date +%Y%m%d_%H%M%S)"
  outdir="${OUT_BASE}/${ts}_QUOTE"
  mkdir -p "$outdir"

  # Fresh nonce (hex)
  local NONCE_HEX
  NONCE_HEX="$(openssl rand -hex 20)"
  printf "%s" "$NONCE_HEX" > "${outdir}/nonce.hex"

  ensure_ak_pub

  log "Generating quote over PCRs (${PCRS_SPEC})"
  # Choose which AK to use for -c: handle or context
  local ak_ref
  if [ -n "${AK_CTX:-}" ] && [ -f "$AK_CTX" ]; then
    ak_ref="$AK_CTX"
  else
    ak_ref="$AK_HANDLE"
  fi

  # Produce the quote
  tpm2_quote \
    -c "$ak_ref" \
    -l "$PCRS_SPEC" \
    -g "$HASH_ALG" \
    -q "$NONCE_HEX" \
    -m "${outdir}/quote.attest" \
    -s "${outdir}/quote.sig" \
    -o "${outdir}/pcrs.bin"

  # Also dump human-readable PCR values for inspection
  # NOTE: tpm2_pcrread takes the bank+list directly, no "-l" flag.
  tpm2_pcrread "$PCRS_SPEC" > "${outdir}/pcrread.txt"

  # Minimal metadata for bookkeeping
  cat > "${outdir}/quote_meta.json" <<EOF
{
  "timestamp": "${ts}",
  "pcrs_spec": "${PCRS_SPEC}",
  "hash_alg": "${HASH_ALG}",
  "nonce_hex_file": "nonce.hex",
  "attest_file": "quote.attest",
  "sig_file": "quote.sig",
  "pcrs_map_file": "pcrs.bin",
  "pcrread_text": "pcrread.txt",
  "ak_pub_file": "$(realpath -m "$AK_PUB" 2>/dev/null || echo "$AK_PUB")"
}
EOF

  log "Quote generated."
  echo "Artifacts in: $outdir"
  printf "  %s\n" "${outdir}/nonce.hex" \
                 "${outdir}/quote.attest" \
                 "${outdir}/quote.sig" \
                 "${outdir}/pcrs.bin" \
                 "${outdir}/pcrread.txt" \
                 "${outdir}/quote_meta.json"
}

main "$@"
