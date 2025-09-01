#!/usr/bin/env bash
set -euo pipefail

# --- Config -------------------------------------------------------------------
WORKDIR="/var/lib/sonic/attestation"
mkdir -p "$WORKDIR" "$WORKDIR/quotes"

# Persistent handles (override via env if needed)
EK_HANDLE="${EK_HANDLE:-0x81010001}"
AK_HANDLE="${AK_HANDLE:-0x81010002}"

# Files
EK_CTX="${EK_CTX:-${WORKDIR}/ek.ctx}"
EK_PUB="${EK_PUB:-${WORKDIR}/ek.pub}"
AK_CTX="${AK_CTX:-${WORKDIR}/ak.ctx}"
AK_PUB="${AK_PUB:-${WORKDIR}/ak.pub}"
AK_NAME="${AK_NAME:-${WORKDIR}/ak.name}"

# Optional hierarchy passwords (leave empty if none)
OWNER_AUTH="${OWNER_AUTH:-}"
ENDORSE_AUTH="${ENDORSE_AUTH:-}"

# Quote config
PCRS_SPEC="${PCRS_SPEC:-sha256:13,14,15}"
HASH_ALG="${HASH_ALG:-sha256}"

# --- Helpers ------------------------------------------------------------------
log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

detect_tcti() {
  if [[ -e /dev/tpmrm0 ]]; then echo "device:/dev/tpmrm0"; return; fi
  if [[ -e /dev/tpm0   ]]; then echo "device:/dev/tpm0";   return; fi
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [[ -S "$sock" && -S "${sock}.ctrl" ]]; then echo "swtpm:path=${sock}"; return; fi
  echo ""
}

evict_if_exists() {
  local handle="$1"
  if tpm2_readpublic -c "$handle" >/dev/null 2>&1; then
    log "Found existing object at $handle, evicting…"
    if [[ -n "$OWNER_AUTH" ]]; then
      tpm2_evictcontrol -C o -P "$OWNER_AUTH" -c "$handle" >/dev/null
    else
      tpm2_evictcontrol -C o -c "$handle" >/dev/null
    fi
    log "Evicted $handle."
  fi
}

# --- Provision EK + AK --------------------------------------------------------
provision_ek_ak() {
  # Clean stale contexts
  rm -f "$EK_CTX" "$AK_CTX"

  log "Creating EK (RSA)…"
  if [[ -n "$ENDORSE_AUTH" ]]; then
    tpm2_createek -G rsa -c "$EK_CTX" -u "$EK_PUB" -f pem -p "$ENDORSE_AUTH" >/dev/null
  else
    tpm2_createek -G rsa -c "$EK_CTX" -u "$EK_PUB" -f pem >/dev/null
  fi

  evict_if_exists "$EK_HANDLE"
  if [[ -n "$OWNER_AUTH" ]]; then
    tpm2_evictcontrol -C o -P "$OWNER_AUTH" -c "$EK_CTX" "$EK_HANDLE" >/dev/null
  else
    tpm2_evictcontrol -C o -c "$EK_CTX" "$EK_HANDLE" >/dev/null
  fi
  log "EK persisted at ${EK_HANDLE}."

  log "Creating AK (RSA, sha256, RSASSA)…"
  tpm2_createak \
    -C "$EK_HANDLE" \
    -G rsa \
    -g sha256 \
    -s rsassa \
    -u "$AK_PUB" \
    -n "$AK_NAME" \
    -c "$AK_CTX" \
    >/dev/null

  evict_if_exists "$AK_HANDLE"
  if [[ -n "$OWNER_AUTH" ]]; then
    tpm2_evictcontrol -C o -P "$OWNER_AUTH" -c "$AK_CTX" "$AK_HANDLE" >/dev/null
  else
    tpm2_evictcontrol -C o -c "$AK_CTX" "$AK_HANDLE" >/dev/null
  fi
  log "AK persisted at ${AK_HANDLE}."

  # Tighten perms
  chmod 0600 "$EK_PUB" "$AK_PUB" "$AK_NAME" || true
}

# --- Quote + Verify -----------------------------------------------------------
quote_and_verify() {
  local ts outdir
  ts="$(date +%Y%m%d_%H%M%S)"
  outdir="${WORKDIR}/quotes/${ts}"
  mkdir -p "$outdir"

  # Fresh nonce (hex)
  local NONCE_HEX
  NONCE_HEX="$(openssl rand -hex 20)"
  printf "%s" "$NONCE_HEX" > "${outdir}/nonce.hex"

  log "Generating quote on PCRs (${PCRS_SPEC}) with AK ${AK_HANDLE}…"
  # Outputs:
  #   -m: TPMS_ATTEST structure
  #   -s: signature
  #   -o: PCR selection+digest (map)
  #   -g: sig/hash alg for quote (should match PCR bank alg)
  #   -q: qualifying data (nonce), hex is accepted by modern tpm2-tools
  tpm2_quote \
    -c "$AK_HANDLE" \
    -l "$PCRS_SPEC" \
    -g "$HASH_ALG" \
    -q "$NONCE_HEX" \
    -m "${outdir}/quote.attest" \
    -s "${outdir}/quote.sig" \
    -o "${outdir}/pcrs.bin"

  # Also dump the actual PCR values we claimed to quote (debug/inspection)
  tpm2_pcrread "$PCRS_SPEC" > "${outdir}/pcrread.txt"

  log "Verifying quote signature with AK public key…"
  # -u AK public, -g hash alg (must match -g used in quote), -f PCR map file
  # -m attest blob, -s signature, -q nonce (same value)
  tpm2_checkquote \
    -u "$AK_PUB" \
    -g "$HASH_ALG" \
    -m "${outdir}/quote.attest" \
    -s "${outdir}/quote.sig" \
    -f "${outdir}/pcrs.bin" \
    -q "$NONCE_HEX" \
    > "${outdir}/verification.txt"
    

  log "Quote + signature verified. Artifacts in: ${outdir}"
  echo "Artifacts:"
  echo "  Nonce (hex):         ${outdir}/nonce.hex"
  echo "  TPMS_ATTEST blob:    ${outdir}/quote.attest"
  echo "  Signature:           ${outdir}/quote.sig"
  echo "  PCR map (binary):    ${outdir}/pcrs.bin"
  echo "  PCR values (text):   ${outdir}/pcrread.txt"
  echo "  Verification output: ${outdir}/verification.txt"
}

# --- Main ---------------------------------------------------------------------
main() {
  # TCTI
  if [[ -z "${TPM2TOOLS_TCTI:-}" ]]; then
    TCTI="$(detect_tcti)"
    [[ -n "$TCTI" ]] || { echo "No TPM TCTI found"; exit 1; }
    export TPM2TOOLS_TCTI="$TCTI"
  fi
  log "Using TCTI: ${TPM2TOOLS_TCTI}"

  provision_ek_ak
  quote_and_verify
}

main "$@"
