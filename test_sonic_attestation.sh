#!/usr/bin/env bash
# End-to-end test runner for the SONiC attestation toolchain.
# Safe in SONiC (dash default) because we force bash via shebang.
# - Strict mode
# - Auto-detect TCTI (prefers device:/dev/tpmrm0)
# - Clear logs, run each stage, fail fast with helpful messages.

set -euo pipefail

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

detect_tcti() {
  if [ -e /dev/tpmrm0 ]; then echo "device:/dev/tpmrm0"; return; fi
  if [ -e /dev/tpm0 ]; then echo "device:/dev/tpm0"; return; fi
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [ -S "$sock" ] && [ -S "${sock}.ctrl" ]; then echo "swtpm:path=${sock}"; return; fi
  echo ""
}

main() {
  # Resolve repo dir even if called via relative path
  local SCRIPT_DIR
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  log "SONiC Attestation – test start"
  log "Working directory: ${SCRIPT_DIR}"

  # Make sure we’re using a TPM that’s actually reachable from inside the guest
  if [ "${TPM2TOOLS_TCTI:-}" = "" ]; then
    local tcti
    tcti="$(detect_tcti)"
    [ -n "$tcti" ] || die "No TPM device found. Expect /dev/tpmrm0 (QEMU) or /dev/tpm0."
    export TPM2TOOLS_TCTI="$tcti"
  fi
  log "TPM2TOOLS_TCTI='${TPM2TOOLS_TCTI}'"

  # Ensure scripts are executable
  chmod +x \
    "${SCRIPT_DIR}/setup_attestation.sh" \
    "${SCRIPT_DIR}/measure_system.sh" \
    "${SCRIPT_DIR}/generate_quote.sh" \
    "${SCRIPT_DIR}/verify_attestation.sh"

  # Clean logs
  local LOGDIR="/var/lib/sonic/attestation/logs"
  mkdir -p "$LOGDIR"
  : > "${LOGDIR}/test.log"

  {
    echo "==== $(date -Iseconds) ===="
    echo "TCTI=${TPM2TOOLS_TCTI}"
    echo

    echo "[1/4] Setup (EK/AK)…"
    "${SCRIPT_DIR}/setup_attestation.sh"
    echo "OK"
    echo

    echo "[2/4] Measure system → extend PCR9…"
    "${SCRIPT_DIR}/measure_system.sh"
    echo "OK"
    echo

    echo "[3/4] Generate Quote…"
    "${SCRIPT_DIR}/generate_quote.sh"
    echo "OK"
    echo

    echo "[4/4] Verify Quote…"
    "${SCRIPT_DIR}/verify_attestation.sh"
    echo "OK"
    echo

    echo "PCR snapshot (sha256:0,7,9):"
    tpm2_pcrread sha256:0,7,9 || true
  } | tee -a "${LOGDIR}/test.log"

  log "All steps completed. Full log: ${LOGDIR}/test.log"
}

main "$@"

