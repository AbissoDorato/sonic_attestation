#!/usr/bin/env bash
set -euo pipefail

# ------------------------------------------------------------
# Export AK identity (Name + TPMT_PUBLIC SHA256)
# Usage: ./get_id_ak.sh [AK_HANDLE] [OUT_DIR]
# ------------------------------------------------------------

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }
die() { log "ERROR: $*"; exit 1; }

# -------- Config / Args --------
OUT_DIR="${2:-/var/lib/sonic/attestation}"
mkdir -p "$OUT_DIR"

# Prefer handle from file, else arg, else env, else default (your AK = 0x81010002)
FILE_HANDLE=""
[ -f "${OUT_DIR}/ak.handle" ] && FILE_HANDLE="$(cat "${OUT_DIR}/ak.handle" || true)"
AK_HANDLE="${1:-${FILE_HANDLE:-${AK_HANDLE:-0x81010002}}}"

# -------- TCTI detection (like your provisioner) --------
detect_tcti() {
  if [[ -e /dev/tpmrm0 ]]; then echo "device:/dev/tpmrm0"; return; fi
  if [[ -e /dev/tpm0   ]]; then echo "device:/dev/tpm0";   return; fi
  local sock="/var/lib/swtpm/mytpm1/sock"
  [[ -S "$sock" ]] && { echo "swtpm:path=${sock}"; return; }
  echo ""
}

if [[ -z "${TPM2TOOLS_TCTI:-}" ]]; then
  TCTI="$(detect_tcti)"
  [[ -n "$TCTI" ]] || die "No TPM TCTI found (no /dev/tpmrm0, /dev/tpm0, or swtpm sock)."
  export TPM2TOOLS_TCTI="$TCTI"
fi
log "Using TCTI: ${TPM2TOOLS_TCTI}"
log "Using AK handle: ${AK_HANDLE}"

# -------- Sanity tools --------
command -v tpm2_readpublic >/dev/null 2>&1 || die "tpm2-tools not found"
command -v xxd >/dev/null 2>&1 || die "xxd not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

# -------- Confirm handle exists (same endpoint) --------
log "Listing persistent handles on this TCTI:"
tpm2_getcap handles-persistent || true

if ! tpm2_readpublic -c "${AK_HANDLE}" >/dev/null 2>&1; then
  die "tpm2_readpublic cannot read ${AK_HANDLE} on this TCTI. Check that provisioning and export use the SAME TPM endpoint (TCTI) and the handle is correct."
fi

# -------- 1) AK Name (TPM-native) --------
NAME_HEX_FILE="${OUT_DIR}/ak.name.hex"
tmp_name_bin="$(mktemp)"
trap 'rm -f "$tmp_name_bin"' EXIT

log "Reading AK Name for ${AK_HANDLE}…"
tpm2_readpublic -c "${AK_HANDLE}" -n "${tmp_name_bin}"
xxd -p -c999 "${tmp_name_bin}" > "${NAME_HEX_FILE}"
chmod 0644 "${NAME_HEX_FILE}"

# -------- 2) TPMT_PUBLIC (TSS) + SHA-256 --------
TSS_FILE="${OUT_DIR}/ak.tss"
TSS_SHA_FILE="${OUT_DIR}/ak.tss.sha256"

log "Reading TPMT_PUBLIC (TSS) for ${AK_HANDLE}…"
tpm2_readpublic -c "${AK_HANDLE}" -f tss -o "${TSS_FILE}"
chmod 0644 "${TSS_FILE}"

log "Computing SHA-256 for TPMT_PUBLIC…"
sha256sum "${TSS_FILE}" | awk '{print $1}' > "${TSS_SHA_FILE}"
chmod 0644 "${TSS_SHA_FILE}"

# -------- Output summary --------
AK_NAME_HEX="$(cat "${NAME_HEX_FILE}")"
AK_TSS_SHA256="$(cat "${TSS_SHA_FILE}")"

log "AK Name (hex): ${AK_NAME_HEX}"
log "AK TSS SHA-256: ${AK_TSS_SHA256}"
log "Wrote:"
log "  - ${NAME_HEX_FILE}"
log "  - ${TSS_FILE}"
log "  - ${TSS_SHA_FILE}"

# Create YAML output file
YAML_FILE="${OUT_DIR}/ak_identity.yaml"
cat > "${YAML_FILE}" <<YAML
# --- Attestation Key Identity ---
ak_identity:
  ak_name_hex: "${AK_NAME_HEX}"
  ak_tss_sha256: "${AK_TSS_SHA256}"
YAML

log "YAML identity saved to: ${YAML_FILE}"
chmod 0644 "${YAML_FILE}"

# Show the contents for verification
log "Contents of ${YAML_FILE}:"
cat "${YAML_FILE}"
