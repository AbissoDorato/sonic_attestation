#!/usr/bin/env bash
# Robust system measurement for SONiC
# - Shell-safe: /bin/bash with set -euo pipefail
# - TCTI auto-detection: prefers device:/dev/tpmrm0
# - Canonical artifacts under /var/lib/sonic/measurements
# PCR mapping:
#   Considering that 
#   from 8 to 15 can be used 
#   the thing that we have to measure are
#   routing state, sonic config, hw/sw baseline
#   we can use 13 (routing) 14 (sonic config) 15 (hw/sw baseline)
#   - (Optional app-specific) -> 

set -euo pipefail

log() { printf "[%(%F %T)T] %s\n" -1 "$*"; }

detect_tcti() {
  if [ -e /dev/tpmrm0 ]; then
    echo "device:/dev/tpmrm0"; return
  fi
  if [ -e /dev/tpm0 ]; then
    echo "device:/dev/tpm0"; return
  fi
  # Allow in-guest swtpm sockets only if both sockets exist (data + ctrl)
  local sock="/run/swtpm/sonic/swtpm-sock"
  if [ -S "$sock" ] && [ -S "${sock}.ctrl" ]; then
    echo "swtpm:path=${sock}"; return
  fi
  echo ""
}

# Hash a file and extend a specific PCR (second arg)
extend_pcr() {
  # $1: path to a file to hash and extend
  # $2: PCR index to extend
  local file="$1"
  local pcr="$2"
  local sum
  sum="$(sha256sum "$file" | awk '{print $1}')"
  # Extend as sha256:HASH
  tpm2_pcrextend "${pcr}:sha256=${sum}" >/dev/null
  printf "%s  %s  PCR=%s\n" "$sum" "$file" "$pcr" >> "${WORKDIR}/measurements.txt"
}

main() {
  log "Starting system measurements..."
  export WORKDIR="/var/lib/sonic/measurements"
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

  ############################
  # PCR 13 - ROUTING STATE
  ############################
  if command -v ip >/dev/null 2>&1; then
    {
      ip -d route show table main || true
      ip -d rule show || true
      # Optional: include per-table dumps if you use RT tables beyond 'main'
      for t in $(awk '/^[0-9]+/ {print $1}' /etc/iproute2/rt_tables 2>/dev/null || true); do
        ip -d route show table "$t" 2>/dev/null || true
      done
      # BGP RIB/FIB snapshots (best effort)
      if command -v vtysh >/dev/null 2>&1; then
        vtysh -c 'show ip bgp summary'           2>/dev/null || true
        vtysh -c 'show ip bgp'                   2>/dev/null || true
        vtysh -c 'show bgp ipv6'                 2>/dev/null || true
        vtysh -c 'show ip route'                 2>/dev/null || true
        vtysh -c 'show bgp l2vpn evpn route'     2>/dev/null || true
      fi
    } > "${WORKDIR}/routes.txt"
    extend_pcr "${WORKDIR}/routes.txt" "13"
  fi

  ############################
  # PCR 14 - SONiC CONFIG
  ############################
  if [ -f /etc/sonic/config_db.json ]; then
    cp /etc/sonic/config_db.json "${WORKDIR}/config_db.json"
    extend_pcr "${WORKDIR}/config_db.json" "14"
  else
    log "WARN: /etc/sonic/config_db.json not found"
  fi

  # FRR running config (best effort)
  # Prefer running-config via vtysh; fallback to static file if readable.
  if command -v vtysh >/dev/null 2>&1; then
    vtysh -c 'show running-config' > "${WORKDIR}/frr_running.conf" 2>/dev/null || true
    if [ -s "${WORKDIR}/frr_running.conf" ]; then
      extend_pcr "${WORKDIR}/frr_running.conf" "14"
    fi
  fi
  if [ -r /etc/sonic/frr/frr.conf ]; then
    cp /etc/sonic/frr/frr.conf "${WORKDIR}/frr.conf"
    extend_pcr "${WORKDIR}/frr.conf" "14"
  fi

  

  ############################
  # PCR 15 - HW & SW BASELINE
  ############################

  # Interfaces + addressing
  {
    ip -br link show || true
    ip addr show     || true
  } > "${WORKDIR}/ifaces.txt"
  extend_pcr "${WORKDIR}/ifaces.txt" "15"

  # Per-interface driver info
  if command -v ethtool >/dev/null 2>&1; then
    : > "${WORKDIR}/drivers.txt"
    for i in $(ls /sys/class/net 2>/dev/null || true); do
      ethtool -i "$i" 2>/dev/null || true
    done >> "${WORKDIR}/drivers.txt"
    [ -s "${WORKDIR}/drivers.txt" ] && extend_pcr "${WORKDIR}/drivers.txt" "15"
  fi

  # Loaded modules
  if command -v lsmod >/dev/null 2>&1; then
    lsmod > "${WORKDIR}/modules.txt"
    extend_pcr "${WORKDIR}/modules.txt" "15"
  fi

  ############################
  # Final PCR reads
  ############################
  log "Final PCR 13 (SONiC config):"
  tpm2_pcrread sha256:13 | sed 's/^/ /'
  log "Final PCR 14 (Routing state):"
  tpm2_pcrread sha256:14 | sed 's/^/ /'
  log "Final PCR 15 (HW & SW base):"
  tpm2_pcrread sha256:15 | sed 's/^/ /'

  log "System measurements completed successfully."
  log "Measurements saved to: ${WORKDIR}/measurements.txt"
}

main "$@"
