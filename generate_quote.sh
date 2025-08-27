#!/usr/bin/env sh
# SONiC quote generator (QEMU+swtpm) — uses saved AK at /var/lib/sonic/attestation
set -eu

# ---- Paths from your setup (as in your log) ----
ATTEST_DIR="${ATTEST_DIR:-/var/lib/sonic/attestation}"
EK_CTX="${EK_CTX:-$ATTEST_DIR/ek.ctx}"
AK_CTX="${AK_CTX:-$ATTEST_DIR/ak.ctx}"
AK_NAME="${AK_NAME:-$ATTEST_DIR/ak.name}"
# Optional persistent handle to reuse if available:
AK_HANDLE="${AK_HANDLE:-0x81000010}"

# ---- Output ----
OUT_DIR="${OUT_DIR:-$ATTEST_DIR/out}"
PCR_LIST="${PCR_LIST:-sha256:0,2,7}"
NONCE_BYTES="${NONCE_BYTES:-32}"

log() { printf '%s\n' "[$(date +'%F %T')] $*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

detect_tcti() {
  if [ -c /dev/tpmrm0 ]; then echo "device:/dev/tpmrm0"; return; fi
  if [ -c /dev/tpm0 ];   then echo "device:/dev/tpm0";   return; fi
  die "No TPM device found (/dev/tpmrm0 or /dev/tpm0). Check your QEMU -tpmdev/-device flags."
}

need_tools() {
  for x in tpm2_getcap tpm2_quote tpm2_pcrread tpm2_readpublic jq base64; do
    command -v "$x" >/dev/null 2>&1 || die "Missing tool: $x"
  done
}

pick_ak_ref() {
  # Prefer your saved AK context file; else persistent handle if valid
  if [ -s "$AK_CTX" ]; then
    echo "$AK_CTX"
    return
  fi
  if tpm2_readpublic -c "$AK_HANDLE" >/dev/null 2>&1; then
    echo "$AK_HANDLE"
    return
  fi
  die "No AK found. Expected $AK_CTX or persistent $AK_HANDLE. Run setup_attestation.sh first."
}

main() {
  need_tools
  mkdir -p "$OUT_DIR"

  export TPM2TOOLS_TCTI="$(detect_tcti)"
  log "TCTI: $TPM2TOOLS_TCTI"

  # Sanity check the TPM
  tpm2_getcap properties-fixed > "$OUT_DIR/tpm_properties.json" 2>/dev/null || \
    die "Cannot talk to TPM via $TPM2TOOLS_TCTI"

  AK_REF="$(pick_ak_ref)"
  log "Using AK: $AK_REF"

  # Nonce (anti-replay)
  if ! tpm2_getrandom "$NONCE_BYTES" > "$OUT_DIR/nonce.bin" 2>/dev/null; then
    log "tpm2_getrandom failed; falling back to /dev/urandom"
    dd if=/dev/urandom of="$OUT_DIR/nonce.bin" bs="$NONCE_BYTES" count=1 status=none
  fi

  # Produce quote
  tpm2_quote -Q \
    -c "$AK_REF" \
    -l "$PCR_LIST" \
    -q "$OUT_DIR/nonce.bin" \
    -m "$OUT_DIR/attest.msg" \
    -s "$OUT_DIR/attest.sig" \
    -o "$OUT_DIR/attest.quote" \
    --validation "$OUT_DIR/attest.validation" >/dev/null

  # PCR snapshot
  tpm2_pcrread "$PCR_LIST" > "$OUT_DIR/pcrs.json"

  # For verifier convenience include AK public (from ctx or handle)
  tpm2_readpublic -c "$AK_REF" > "$OUT_DIR/ak_readpublic.json"

  # Bundle
  {
    printf '{\n'
    printf '  "tcti": %s,\n'           "$(printf '%s' "$TPM2TOOLS_TCTI" | jq -R '.')"
    printf '  "ak_ref": %s,\n'          "$(printf '%s' "$AK_REF" | jq -R '.')"
    printf '  "pcr_list": %s,\n'         "$(printf '%s' "$PCR_LIST" | jq -R '.')"
    printf '  "nonce_b64": %s,\n'        "$(base64 -w0 < "$OUT_DIR/nonce.bin" | jq -R '.')"
    printf '  "ak_public": %s,\n'        "$(jq -c . < "$OUT_DIR/ak_readpublic.json")"
    printf '  "pcrs": %s,\n'             "$(jq -c . < "$OUT_DIR/pcrs.json")"
    printf '  "attest_msg_b64": %s,\n'   "$(base64 -w0 < "$OUT_DIR/attest.msg" | jq -R '.')"
    printf '  "attest_sig_b64": %s,\n'   "$(base64 -w0 < "$OUT_DIR/attest.sig" | jq -R '.')"
    printf '  "attest_quote_b64": %s\n'  "$(base64 -w0 < "$OUT_DIR/attest.quote" | jq -R '.')"
    printf '}\n'
  } > "$OUT_DIR/quote_bundle.json"

  log "Quote OK → $OUT_DIR/quote_bundle.json"
}

main "$@"

