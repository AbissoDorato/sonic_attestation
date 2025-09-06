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
#   ./generate_quote.sh [options]
#     -d, --dir DIR          Output directory base (default: /var/lib/sonic/attestation/quotes)
#     -n, --nonce NONCE      Use specific nonce (40 hex chars, default: random)
#     -h, --help             Show this help
# ============================================================

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }
error() { printf "[%(%F %T)T] ERROR: %s\n" -1 "$*" >&2; }

# ---------------- Config / Defaults ----------------
: "${CONF:=/etc/sonic/attestation/attestation.conf}"
: "${STATE_DIR:=/var/lib/sonic/attestation}"

# Default values
OUT_BASE="${STATE_DIR}/quotes"
NONCE_HEX=""

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

# ---------------- Help Function ----------------
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Generate TPM2 attestation quote with proper validation.

Options:
    -d, --dir DIR          Output directory base (default: $OUT_BASE)
    -n, --nonce NONCE      Use specific nonce (40 hex characters)
                          If not provided, a random nonce will be generated
    -h, --help            Show this help message

Examples:
    $0                                    # Use defaults
    $0 -d /tmp/quotes                    # Custom output directory
    $0 -n 1234567890abcdef1234567890abcdef12345678  # Custom nonce
    $0 -d /tmp/quotes -n 1234567890abcdef1234567890abcdef12345678  # Both

Note: Nonce must be exactly 40 hexadecimal characters (0-9, a-f, A-F)
EOF
}

# ---------------- Validation Functions ----------------
validate_nonce() {
    local nonce="$1"
    
    # Check length (40 hex chars = 20 bytes)
    if [ ${#nonce} -ne 40 ]; then
        error "Nonce must be exactly 40 hexadecimal characters, got ${#nonce}"
        return 1
    fi
    
    # Check if it's valid hex
    if ! [[ "$nonce" =~ ^[0-9a-fA-F]{40}$ ]]; then
        error "Nonce must contain only hexadecimal characters (0-9, a-f, A-F)"
        return 1
    fi
    
    return 0
}

validate_output_dir() {
    local dir="$1"
    
    # Check if parent directory exists and is writable
    local parent_dir="$(dirname "$dir")"
    
    if [ ! -d "$parent_dir" ]; then
        error "Parent directory does not exist: $parent_dir"
        return 1
    fi
    
    if [ ! -w "$parent_dir" ]; then
        error "Parent directory is not writable: $parent_dir"
        return 1
    fi
    
    # If the target directory exists, check if it's writable
    if [ -e "$dir" ]; then
        if [ ! -d "$dir" ]; then
            error "Path exists but is not a directory: $dir"
            return 1
        fi
        if [ ! -w "$dir" ]; then
            error "Directory is not writable: $dir"
            return 1
        fi
    fi
    
    return 0
}

# ---------------- Argument Parsing ----------------
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                if [ -z "${2:-}" ]; then
                    error "Option $1 requires a directory path"
                    exit 1
                fi
                OUT_BASE="$2"
                shift 2
                ;;
            -n|--nonce)
                if [ -z "${2:-}" ]; then
                    error "Option $1 requires a nonce value"
                    exit 1
                fi
                NONCE_HEX="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                show_help
                exit 1
                ;;
            *)
                error "Unexpected argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

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
preflight_checks() {
    command -v tpm2_quote >/dev/null 2>&1 || { error "Missing tpm2-tools (tpm2_quote)"; exit 1; }
    command -v tpm2_pcrread >/dev/null 2>&1 || { error "Missing tpm2-tools (tpm2_pcrread)"; exit 1; }
    command -v tpm2_readpublic >/dev/null 2>&1 || true
    command -v openssl >/dev/null 2>&1 || { error "Missing openssl"; exit 1; }

    TCTI="$(detect_tcti)"
    if [ -z "$TCTI" ]; then
        error "No TPM available"
        exit 1
    fi
    export TPM2TOOLS_TCTI="$TCTI"
}

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
  [ -s "$AK_PUB" ] || { error "Failed to obtain AK public key"; exit 1; }
}

main() {
  # Parse and validate arguments
  parse_arguments "$@"
  
  # Validate output directory
  if ! validate_output_dir "$OUT_BASE"; then
    exit 1
  fi
  
  # Validate nonce if provided
  if [ -n "$NONCE_HEX" ]; then
    if ! validate_nonce "$NONCE_HEX"; then
      exit 1
    fi
    log "Using provided nonce: $NONCE_HEX"
  else
    NONCE_HEX="$(openssl rand -hex 20)"
    log "Generated random nonce: $NONCE_HEX"
  fi
  
  # Run preflight checks
  preflight_checks
  
  # Create output directory
  mkdir -p "$OUT_BASE"

  local ts outdir
  ts="$(date +%Y%m%d_%H%M%S)"
  outdir="${OUT_BASE}/${ts}_QUOTE"
  mkdir -p "$outdir"

  # Save nonce
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
  if ! tpm2_quote \
    -c "$ak_ref" \
    -l "$PCRS_SPEC" \
    -g "$HASH_ALG" \
    -q "$NONCE_HEX" \
    -m "${outdir}/quote.attest" \
    -s "${outdir}/quote.sig" \
    -o "${outdir}/pcrs.bin"; then
    error "Failed to generate TPM quote"
    exit 1
  fi

  # Also dump human-readable PCR values for inspection
  # NOTE: tpm2_pcrread takes the bank+list directly, no "-l" flag.
  if ! tpm2_pcrread "$PCRS_SPEC" > "${outdir}/pcrread.txt"; then
    error "Failed to read PCR values"
    exit 1
  fi

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

  log "Quote generated successfully."
  echo "Artifacts in: $outdir"
  printf "  %s\n" "${outdir}/nonce.hex" \
                 "${outdir}/quote.attest" \
                 "${outdir}/quote.sig" \
                 "${outdir}/pcrs.bin" \
                 "${outdir}/pcrread.txt" \
                 "${outdir}/quote_meta.json"
}

main "$@"