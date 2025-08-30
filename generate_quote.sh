#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# SONiC Attestation - Quote & PCR Extend Helper
# - Quote PCRs and save artifacts (msg/sig/ticket/pcrs/meta)
# - Extend PCRs with file digests (single file) or a stable
#   bundle-root digest (recommended) before quoting
#
# Usage:
#   ./generate_quote.sh quote [NONCE_HEX] [OUT_DIR]
#   ./generate_quote.sh extend-file  <PCR> <FILE>
#   ./generate_quote.sh extend-bundle <PCR> <FILE...>
#   ./generate_quote.sh help
#
# Notes:
# - Requires: tpm2-tools, openssl, coreutils
# - AK context/public must already exist (generated elsewhere)
# ============================================================

# ---------------- Config / Defaults ----------------
: "${CONF:=/etc/sonic/attestation/attestation.conf}"
: "${STATE_DIR:=/var/lib/sonic/attestation}"
# Default PCR selection for QUOTE (edit as you prefer)
: "${PCR_NUMBER:=14,15,23}"
: "${HALG:=sha256}"
: "${AK_CTX:=${STATE_DIR}/ak.ctx}"
: "${AK_PUB:=${STATE_DIR}/ak.pub}"

[ -f "$CONF" ] && source "$CONF"

# ---------------- Logging helpers ------------------
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------- TPM detection --------------------
detect_tcti() {
  # Prefer kernel resource manager if present
  if [ -e /dev/tpmrm0 ]; then echo "device:/dev/tpmrm0"; return; fi
  if [ -e /dev/tpm0   ]; then echo "device:/dev/tpm0";   return; fi
  # Common swtpm socket path used in our SONiC service
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [ -S "$sock" ] && [ -S "${sock}.ctrl" ]; then echo "swtpm:path=${sock}"; return; fi
  # Fallback: if env is already set, keep it
  if [ -n "${TPM2TOOLS_TCTI:-}" ]; then echo "$TPM2TOOLS_TCTI"; return; fi
  echo ""
}

TCTI="$(detect_tcti)"
[ -n "$TCTI" ] || die "No TPM TCTI found (no /dev/tpmrm0, /dev/tpm0 or swtpm socket)."
export TPM2TOOLS_TCTI="$TCTI"
log "Using TCTI: $TPM2TOOLS_TCTI"

# ---------------- Tool availability ----------------
command -v tpm2_quote >/dev/null 2>&1 || die "tpm2_quote not found"
command -v tpm2_pcrread >/dev/null 2>&1 || die "tpm2_pcrread not found"
command -v tpm2_pcrextend >/dev/null 2>&1 || die "tpm2_pcrextend not found"
command -v openssl >/dev/null 2>&1 || die "openssl not found"

[ -f "$AK_CTX" ] || die "AK context not found at $AK_CTX"
[ -f "$AK_PUB" ] || die "AK public not found at $AK_PUB"

# ---------------- Compatibility helpers ------------
has_opt_quote()      { tpm2_quote  -h 2>&1 | grep -q -- "$1"; }
has_opt_pcrread_L()  { tpm2_pcrread -h 2>&1 | grep -q " -L,"; }

# tpm2_quote changed -l/-L across versions; detect
QUOTE_PCR_OPT="-L"; has_opt_quote " -L," || QUOTE_PCR_OPT="-l"

# ---------------- PCR extend helpers ----------------
# Extend a single file's sha256 into PCR
extend_pcr_file() {
  local pcr="$1"; shift
  local file="$1"
  [ -r "$file" ] || die "File not readable: $file"
  local sum
  sum="$(sha256sum "$file" | awk '{print $1}')"
  log "Extending PCR${pcr} with sha256($file)=${sum}"
  tpm2_pcrextend "${pcr}:sha256=${sum}" >/dev/null
  printf "%s  %s\n" "$sum" "$file"
}

# Extend a stable bundle-root digest into PCR
# This is recommended for "classes" of measurement (config, routing, hw)
extend_pcr_bundle() {
  local pcr="$1"; shift
  [ "$#" -gt 0 ] || die "extend-bundle: no input files"
  local tmp
  tmp="$(mktemp)"
  # Deterministic manifest lines: mode size sha256 path
  for f in "$@"; do
    [ -e "$f" ] || { log "Skip missing: $f"; continue; }
    local sum size mode
    sum="$(sha256sum "$f" | awk '{print $1}')"
    size="$(stat -c '%s' "$f")"
    mode="$(stat -c '%f' "$f")"
    printf '%s %s %s %s\n' "$mode" "$size" "$sum" "$f" >> "$tmp"
  done
  sort -u "$tmp" -o "$tmp"
  local root
  root="$(sha256sum "$tmp" | awk '{print $1}')"
  log "Extending PCR${pcr} with bundle-root=${root} (n=$(wc -l < "$tmp"))"
  tpm2_pcrextend "${pcr}:sha256=${root}" >/dev/null
  echo "bundle-root ${root}"
  rm -f "$tmp"
}

# ---------------- Quote action ---------------------
do_quote() {
  local NONCE_HEX="${1:-$(openssl rand -hex 20)}"
  local OUT_DIR="${2:-${STATE_DIR}/measurements/quote_$(date +%Y%m%d_%H%M%S)}"
  mkdir -p "$OUT_DIR"

  local QUOTE_MSG="${OUT_DIR}/quote.msg"
  local QUOTE_SIG="${OUT_DIR}/quote.sig"
  local QUOTE_TK="${OUT_DIR}/quote.tk"
  local PCRS_YAML="${OUT_DIR}/pcrs.yaml"
  local META_JSON="${OUT_DIR}/quote_meta.json"
  local NONCE_TXT="${OUT_DIR}/nonce_hex.txt"

  local SEL="${HALG}:${PCR_NUMBER}"
  echo -n "$NONCE_HEX" > "$NONCE_TXT"

  log "Dumping PCRs: $SEL"
  if has_opt_pcrread_L; then
    # Newer tools
    tpm2_pcrread -L "$SEL" > "$PCRS_YAML"
  else
    # Older tools
    tpm2_pcrread "$SEL" > "$PCRS_YAML"
  fi

  log "Quoting with AK '$AK_CTX' over $SEL"
  if tpm2_quote -h 2>&1 | grep -q " -t,"; then
    # Ticket supported
    tpm2_quote \
      -c "$AK_CTX" \
      "${QUOTE_PCR_OPT}" "$SEL" \
      -g "$HALG" \
      -q "$NONCE_HEX" \
      -m "$QUOTE_MSG" \
      -s "$QUOTE_SIG" \
      -t "$QUOTE_TK"
  else
    # No ticket flag; still fine
    tpm2_quote \
      -c "$AK_CTX" \
      "${QUOTE_PCR_OPT}" "$SEL" \
      -g "$HALG" \
      -q "$NONCE_HEX" \
      -m "$QUOTE_MSG" \
      -s "$QUOTE_SIG"
    : > "$QUOTE_TK"
  fi

  # Metadata for the verifier
  cat > "$META_JSON" <<EOF
{
  "timestamp": "$(date -Is)",
  "ak_pub": "${AK_PUB}",
  "ak_ctx": "${AK_CTX}",
  "tcti": "${TPM2TOOLS_TCTI}",
  "pcr_selection": "${SEL}",
  "nonce_hex": "${NONCE_HEX}",
  "quote_msg": "$(basename "$QUOTE_MSG")",
  "quote_sig": "$(basename "$QUOTE_SIG")",
  "quote_ticket": "$(basename "$QUOTE_TK")",
  "pcrs_yaml": "$(basename "$PCRS_YAML")",
  "hash_alg": "${HALG}"
}
EOF

  log "Quote saved under: $OUT_DIR"
  echo "Artifacts:"
  printf '  - %s\n' "$PCRS_YAML" "$QUOTE_MSG" "$QUOTE_SIG" "$QUOTE_TK" "$META_JSON" "$NONCE_TXT"
  echo
  echo "Quick verify (local, signature only):"
  echo "  tpm2_verifysignature -c \"$AK_PUB\" -g ${HALG} -m \"$QUOTE_MSG\" -s \"$QUOTE_SIG\""
}

# ---------------- Usage ----------------------------
usage() {
  cat <<EOF
Usage:
  $0 quote [NONCE_HEX] [OUT_DIR]
      Quote PCRs ${PCR_NUMBER} (alg ${HALG}) and save artifacts.

  $0 extend-file <PCR> <FILE>
      Hash <FILE> with sha256 and extend PCR <PCR> once.

  $0 extend-bundle <PCR> <FILE...>
      Build a deterministic manifest over <FILE...>, hash it, and extend PCR <PCR> with the bundle-root.
      Recommended for stability (config/routing/hw classes).

  $0 help
EOF
}

# ---------------- Dispatcher -----------------------
cmd="${1:-quote}"; shift || true
case "$cmd" in
  quote)          do_quote "${1:-}" "${2:-}";;
  extend-file)    [ "$#" -ge 2 ] || die "extend-file requires <PCR> <FILE>"; extend_pcr_file "$1" "$2";;
  extend-bundle)  [ "$#" -ge 2 ] || die "extend-bundle requires <PCR> <FILE...>"; pcr="$1"; shift; extend_pcr_bundle "$pcr" "$@";;
  help|-h|--help) usage;;
  *)              usage; die "Unknown command: $cmd";;
esac
exit 0