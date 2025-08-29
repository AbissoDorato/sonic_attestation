#!/usr/bin/env bash
# Robust system measurement for SONiC
# - Shell-safe: uses bash; avoids [[ ... ]] in case /bin/sh invokes it
# - TCTI auto-detection: prefers device:/dev/tpmrm0
# - Writes canonical artifacts under /var/lib/sonic/measurements

# application pcrr 16-23
# sonic config 17
# sonic routing 18
# sonic hw info 19

set -euo pipefail

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

detect_tcti() {
  if [ -e /dev/tpmrm0 ]; then
    echo "device:/dev/tpmrm0"; return
  fi
  if [ -e /dev/tpm0 ]; then
    echo "device:/dev/tpm0"; return
  fi
  # Optional: allow an in-guest swtpm socket only if BOTH sockets exist
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [ -S "$sock" ] && [ -S "${sock}.ctrl" ]; then
    echo "swtpm:path=${sock}"; return
  fi
  echo ""
}

# function to extend pcrs 

extend_pcr() {
  # $1: path to a file to hash and extend
  local file="$1"
  local pcr="$2"
  local sum
  sum="$(sha256sum "$file" | awk '{print $1}')"
  # Extend as sha256:HASH
  tpm2_pcrextend "$2":sha256="$sum" >/dev/null
  printf "%s  %s\n" "$sum" "$file" >> "${WORKDIR}/measurements.txt"
}

main() {
  log "Starting system measurements..."

  export WORKDIR=/var/lib/sonic/measurements
  mkdir -p "$WORKDIR"
  chmod 700 "$WORKDIR"

  TCTI="$(detect_tcti)"
  if [ -z "$TCTI" ]; then
    echo "ERROR: No TPM device found (/dev/tpmrm0 or /dev/tpm0)."
    echo "       Do NOT point to host swtpm sockets from inside the guest."
    exit 1
  fi
  export TPM2TOOLS_TCTI="$TCTI"
  log "Using TPM2TOOLS_TCTI='${TPM2TOOLS_TCTI}'"

  # Sanity probe
  tpm2_getcap properties-fixed >/dev/null

  : > "${WORKDIR}/measurements.txt"

  # 1) config_db.json
  if [ -f /etc/sonic/config_db.json ]; then
    cp /etc/sonic/config_db.json "${WORKDIR}/config_db.json"
    extend_pcr "${WORKDIR}/config_db.json" "9"
  else
    log "WARN: /etc/sonic/config_db.json not found"
  fi

  # 2) Kernel info
  uname -a > "${WORKDIR}/kernel.txt"
  extend_pcr "${WORKDIR}/kernel.txt" "9"

  # 3) BIOS/DMI (if available)
  if command -v dmidecode >/dev/null 2>&1; then
    dmidecode -t bios > "${WORKDIR}/bios.txt" || true
    extend_pcr "${WORKDIR}/bios.txt" "9"|| true
  fi

  # 4) Routing tables
  if command -v ip >/dev/null 2>&1; then
    {
      ip -d route show table main || true
      ip -d rule show || true
    } > "${WORKDIR}/routes.txt"
    extend_pcr "${WORKDIR}/routes.txt" "9"
  fi

  # 5) Interfaces + driver info
  {
    ip -br link show || true
    ip addr show || true
  } > "${WORKDIR}/ifaces.txt"
  extend_pcr "${WORKDIR}/ifaces.txt" "9"

  # Per-interface driver (best-effort)
  if command -v ethtool >/dev/null 2>&1; then
    : > "${WORKDIR}/drivers.txt"
    for i in $(ls /sys/class/net 2>/dev/null || true); do
      ethtool -i "$i" 2>/dev/null || true
    done >> "${WORKDIR}/drivers.txt"
    extend_pcr "${WORKDIR}/drivers.txt" "9"
  fi

  # 6) Loaded modules
  if command -v lsmod >/dev/null 2>&1; then
    lsmod > "${WORKDIR}/modules.txt"
    extend_pcr "${WORKDIR}/modules.txt" "9"
  fi

  # 7) FRR running config (if readable)
  if [ -r /etc/sonic/frr/frr.conf ]; then
    cp /etc/sonic/frr/frr.conf "${WORKDIR}/frr.conf"
    extend_pcr "${WORKDIR}/frr.conf" "9"
  fi

  # 8) Anything else you want “in policy” — add here.

  log "Final PCR 9 value:"
  tpm2_pcrread sha256:9 | sed 's/^/  /'

  log "Final PCR 17 value:"
  tpm2_pcrread sha256:17 | sed 's/^/  /'

  log "Final PCR 18 value:"
  tpm2_pcrread sha256:18 | sed 's/^/  /'

  log "Final PCR 19 value:"
  tpm2_pcrread sha256:19 | sed 's/^/  /'


  log "System measurements completed successfully"
  log "Measurements saved to: ${WORKDIR}/measurements.txt"
}

main "$@"

