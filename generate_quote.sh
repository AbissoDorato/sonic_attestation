#!/usr/bin/env bash
set -euo pipefail

# --- config / defaults ---
: "${CONF:=/etc/sonic/attestation/attestation.conf}"
: "${STATE_DIR:=/var/lib/sonic/attestation}"
: "${PCR_NUMBER:=9}"
: "${HALG:=sha256}"
: "${AK_CTX:=${STATE_DIR}/ak.ctx}"
: "${AK_PUB:=${STATE_DIR}/ak.pub}"

[ -f "$CONF" ] && source "$CONF"

# Prefer resource manager device when present
if [ -e /dev/tpmrm0 ] && [ -z "${TPM2TOOLS_TCTI:-}" ]; then
  export TPM2TOOLS_TCTI="device:/dev/tpmrm0"
fi

# --- args ---
NONCE_HEX="${1:-$(openssl rand -hex 20)}"
OUT_DIR="${2:-${STATE_DIR}/measurements/quote_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUT_DIR"

# Files
QUOTE_MSG="${OUT_DIR}/quote.msg"
QUOTE_SIG="${OUT_DIR}/quote.sig"
QUOTE_TK="${OUT_DIR}/quote.tk"
PCRS_YAML="${OUT_DIR}/pcrs.yaml"
META_JSON="${OUT_DIR}/quote_meta.json"

# Helpers to handle version diffs across tpm2-tools
has_opt_quote() { tpm2_quote -h 2>&1 | grep -q -- "$1"; }
has_opt_pcrread_L() { tpm2_pcrread -h 2>&1 | grep -q " -L,"; }

# tpm2_quote changed -l/-L across versions; detect
QUOTE_PCR_OPT="-L"; has_opt_quote " -L," || QUOTE_PCR_OPT="-l"

command -v tpm2_quote >/dev/null
command -v tpm2_pcrread >/dev/null
[ -f "$AK_CTX" ] || { echo "AK context not found at $AK_CTX" >&2; exit 1; }
[ -f "$AK_PUB" ] || { echo "AK public not found at $AK_PUB" >&2; exit 1; }

SEL="${HALG}:${PCR_NUMBER}"

# ---- Evidence binding (qualifying data) ----
# Choose which files define your "measurement bundle" (stable, canonicalized)
# Example: measurements.json + normalized routing dump + bios/kver summaries
BUNDLE_FILES=()
[ -f "${OUT_DIR}/measurements.json" ] && BUNDLE_FILES+=("${OUT_DIR}/measurements.json")
[ -f "${OUT_DIR}/routing.txt" ]       && BUNDLE_FILES+=("${OUT_DIR}/routing.txt")
[ -f "${OUT_DIR}/kernel.txt" ]        && BUNDLE_FILES+=("${OUT_DIR}/kernel.txt")
[ -f "${OUT_DIR}/bios.txt" ]          && BUNDLE_FILES+=("${OUT_DIR}/bios.txt")

# Create a reproducible manifest (name + sha256) and a single bundle hash
MANIFEST="${OUT_DIR}/evidence_manifest.txt"
> "$MANIFEST"
for f in "${BUNDLE_FILES[@]}"; do
  # hash only content; include stable file names to avoid reordering ambiguity
  printf "%s  %s\n" "$(sha256sum "$f" | awk '{print tolower($1)}')" "$(basename "$f")" >> "$MANIFEST"
done
BUNDLE_HASH="$(sha256sum "$MANIFEST" | awk '{print tolower($1)}')"

# Mix in your random nonce to prevent replay; store both for the verifier
echo -n "$NONCE_HEX" > "${OUT_DIR}/nonce.txt"
printf "%s:%s" "$NONCE_HEX" "$BUNDLE_HASH" > "${OUT_DIR}/qual.bin"




# ---- Dump PCRs (portable) ----
if has_opt_pcrread_L; then
  # Newer tools: tpm2_pcrread -L sha256:9
  tpm2_pcrread -L "$SEL" > "$PCRS_YAML"
else
  # Older tools: tpm2_pcrread sha256:9
  tpm2_pcrread "$SEL" > "$PCRS_YAML"
fi

if tpm2_quote -h 2>&1 | grep -q " -o,"; then
  tpm2_quote \
    -c "$AK_CTX" \
    "${QUOTE_PCR_OPT}" "$SEL" \
    -g "$HALG" \
    -q "$NONCE_HEX" \
    -m "$QUOTE_MSG" \
    -s "$QUOTE_SIG" \
    -o "$QUOTE_TK"
else
  tpm2_quote \
    -c "$AK_CTX" \
    "${QUOTE_PCR_OPT}" "$SEL" \
    -g "$HALG" \
    -q "$NONCE_HEX" \
    -m "$QUOTE_MSG" \
    -s "$QUOTE_SIG"
fi

# ---- Metadata ----
cat > "$META_JSON" <<EOF
{
  "timestamp": "$(date -Is)",
  "ak_pub": "${AK_PUB}",
  "pcr_selection": "${SEL}",
  "nonce_hex": "${NONCE_HEX}",
  "quote_msg": "$(basename "$QUOTE_MSG")",
  "quote_sig": "$(basename "$QUOTE_SIG")",
  "quote_ticket": "$(basename "$QUOTE_TK")",
  "pcrs_yaml": "$(basename "$PCRS_YAML")",
  "hash_alg": "${HALG}"
}
EOF

echo "Quote generated under: $OUT_DIR"
echo "Nonce: $NONCE_HEX"
