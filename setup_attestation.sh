#!/usr/bin/env bash
set -euo pipefail

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

# --- Detect TPM access method -------------------------------------------------
detect_tcti() {
  # Prefer the in-kernel resource manager exposed by QEMU
  if [[ -e /dev/tpmrm0 ]]; then
    echo "device:/dev/tpmrm0"
    return
  fi
  # Fallback to raw char device
  if [[ -e /dev/tpm0 ]]; then
    echo "device:/dev/tpm0"
    return
  fi
  # As a last resort, allow an in-guest swtpm socket if user truly set it up.
  local SOCK="/run/swtpm/sonic/swtpm-sock"
  if [[ -S "${SOCK}" && -S "${SOCK}.ctrl" ]]; then
    echo "swtpm:path=${SOCK}"
    return
  fi
  echo ""
}

main() {
  log "Starting SONiC Attestation System setup..."

  # Ensure we can access the TPM
  TCTI="$(detect_tcti)"
  if [[ -z "${TCTI}" ]]; then
    echo "ERROR: No TPM device found. Expected /dev/tpmrm0 or /dev/tpm0 (from QEMU)."
    echo "       If you really want to use an in-guest swtpm, create BOTH sockets:"
    echo "       /run/swtpm/sonic/swtpm-sock and /run/swtpm/sonic/swtpm-sock.ctrl"
    exit 1
  fi
  export TPM2TOOLS_TCTI="${TCTI}"
  log "Using TPM2TOOLS_TCTI='${TPM2TOOLS_TCTI}'"

  # Never try to spawn swtpm if we have a device TCTI.
  if [[ "${TPM2TOOLS_TCTI}" == device:* ]]; then
    log "Detected QEMU-provided TPM device; skipping software TPM startup."
  fi

  # --- Prepare dirs for keys/artifacts ---------------------------------------
  WORKDIR=/var/lib/sonic/attestation
  mkdir -p "${WORKDIR}"
  chmod 700 "${WORKDIR}"

  EK_CTX="${WORKDIR}/ek.ctx"
  EK_PUB="${WORKDIR}/ek.pub"
  AK_CTX="${WORKDIR}/ak.ctx"
  AK_PUB="${WORKDIR}/ak.pub"
  AK_NAME="${WORKDIR}/ak.name"

  # --- Sanity check TPM and clear lockouts (safe if already clear) -----------
  log "Probing TPM..."
  tpm2_getcap properties-fixed >/dev/null

  # Make sure we won’t be blocked by previous sessions (ignore failures)
  tpm2_clearcontrol -C p c 2>/dev/null || true
  tpm2_clear -C p 2>/dev/null || true

  # --- Create EK (RSA) and persist if desired --------------------------------
  log "Creating Endorsement Key..."
  tpm2_createek -G rsa -c "${EK_CTX}" -u "${EK_PUB}" -Q

  # --- Create AK (ECDSA recommended for quotes) ------------------------------
  log "Creating Attestation Key..."
  tpm2_createak -C "${EK_CTX}" -G ecc -g sha256 -s ecdsa \
    -c "${AK_CTX}" -u "${AK_PUB}" -n "${AK_NAME}" -Q

  # Optional: persist handles (uncomment if you want persistence)
  # tpm2_evictcontrol -C o -c "${EK_CTX}" 0x81010001 -Q
  # tpm2_evictcontrol -C o -c "${AK_CTX}" 0x81010002 -Q

  # --- Health check: take a tiny quote to confirm everything works -----------
  # to be added, add a quote -q just to check for the key to work
  PCRS="sha256:0,7"
  QUOTE="${WORKDIR}/selftest_quote.bin"
  SIG="${WORKDIR}/selftest_sig.bin"
  TPMS="${WORKDIR}/selftest_tpms.bin"
  log "Self-test quote on ${PCRS}..."
  tpm2_quote -c "${AK_CTX}" -l "${PCRS}" -m "${TPMS}" -s "${SIG}" -o "${QUOTE}"

  log "Setup complete. EK/AK generated:"
  log "  EK_CTX=${EK_CTX}"
  log "  AK_CTX=${AK_CTX}"
  log "  AK_NAME=${AK_NAME}"
}

main "$@"

