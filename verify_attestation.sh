#!/bin/bash
# SONiC Attestation Verification System
# verify_attestation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REFERENCE_DB="/var/lib/sonic/attestation/reference_values.db"
LOG_FILE="/var/log/sonic/attestation_verifier.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize reference database
init_reference_db() {
    local db_dir="$(dirname "$REFERENCE_DB")"
    mkdir -p "$db_dir"
    
    if [ ! -f "$REFERENCE_DB" ]; then
        log "Creating reference values database..."
        cat > "$REFERENCE_DB" << 'EOF'
# SONiC Attestation Reference Values Database
# Format: component:subcomponent:expected_hash:description

# Example trusted kernel versions
kernel:version:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456:Linux 5.10.0-sonic
kernel:version:b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a:Linux 5.15.0-sonic

# Example trusted BIOS versions  
firmware:bios_version:c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2:AMI BIOS v2.1.0
firmware:bios_vendor:d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2c3:American Megatrends Inc.

# Example trusted SONiC configurations
sonic:version:e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2c3d4:SONiC.202305.01
sonic:config_db:f6789012345678901234567890abcdef1234567890abcdef1234567ab2c3d4e5:default-config

# Trusted service images
service:container:swss:789012345678901234567890abcdef1234567890abcdef1234567ab2c3d4e5f6:swss-latest
service:container:bgp:89012345678901234567890abcdef1234567890abcdef1234567ab2c3d4e5f67:frr-bgp-8.4

EOF
        log "Reference database created at: $REFERENCE_DB"
    fi
}

# Add reference value to database
add_reference_value() {
    local component="$1"
    local subcomponent="$2" 
    local hash="$3"
    local description="$4"
    
    local entry="$component:$subcomponent:$hash:$description"
    
    # Check if entry already exists
    if grep -q "^$component:$subcomponent:$hash:" "$REFERENCE_DB"; then
        log "Reference value already exists: $entry"
        return 0
    fi
    
    echo "$entry" >> "$REFERENCE_DB"
    log "Added reference value: $entry"
}

# Verify single measurement against reference database
verify_measurement() {
    local measurement="$1"
    
    # Parse measurement (format: component:subcomponent:hash)
    local component=$(echo "$measurement" | awk -F: '{print $1}')
    local subcomponent=$(echo "$measurement" | awk -F: '{print $2}')
    local actual_hash=$(echo "$measurement" | awk -F: '{print $3}')
    
    # Skip final PCR measurement for now
    if [ "$component" = "final_pcr" ]; then
        return 0
    fi
    
    # Look for matching reference values
    local matches=$(grep "^$component:$subcomponent:" "$REFERENCE_DB" | grep -v "^#" || true)
    
    if [ -z "$matches" ]; then
        log "WARNING: No reference values found for $component:$subcomponent"
        return 1
    fi
    
    # Check if actual hash matches any reference value
    local found=0
    while IFS= read -r ref_line; do
        local ref_hash=$(echo "$ref_line" | awk -F: '{print $3}')
        if [ "$actual_hash" = "$ref_hash" ]; then
            local description=$(echo "$ref_line" | awk -F: '{print $4}')
            log "VERIFIED: $component:$subcomponent -> $description"
            found=1
            break
        fi
    done <<< "$matches"
    
    if [ $found -eq 0 ]; then
        log "FAILED: $component:$subcomponent hash $actual_hash not in reference database"
        return 1
    fi
    
    return 0
}

# Verify TPM quote signature
verify_quote_signature() {
    local attestation_dir="$1"
    
    log "Verifying TPM quote signature..."
    
    # Check required files exist
    for file in quote.msg quote.sig ak.pub; do
        if [ ! -f "$attestation_dir/$file" ]; then
            log "ERROR: Missing file: $file"
            return 1
        fi
    done
    
    # Use tpm2_checkquote to verify the quote
    # Note: In real deployment, you'd also verify the AK certificate against a CA
    if tpm2_checkquote --public "$attestation_dir/ak.pub" \
                       --message "$attestation_dir/quote.msg" \
                       --signature "$attestation_dir/quote.sig" \
                       --qualification "$attestation_dir/qualifier.data" \
                       --pcr-list sha256:9 > /dev/null 2>&1; then
        log "TPM quote signature VERIFIED"
        return 0
    else
        log "TPM quote signature FAILED"
        return 1
    fi
}

# Extract PCR value from quote
extract_pcr_from_quote() {
    local attestation_dir="$1"
    local pcr_num="$2"
    
    # This is simplified - in reality you'd parse the TPMS_ATTEST structure
    # For now, we'll extract from the measurements file
    local pcr_value=$(grep "^final_pcr:$pcr_num:" "$attestation_dir/measurements.txt" | awk -F: '{print $3}')
    echo "$pcr_value"
}

# Calculate expected PCR value from measurements
calculate_expected_pcr() {
    local measurements_file="$1"
    local pcr_num="$2"
    
    # Simulate PCR extension calculation
    # Start with PCR reset value (all zeros for SHA256)
    local pcr_value="0000000000000000000000000000000000000000000000000000000000000000"
    
    # Extend each measurement (simplified - real implementation would use proper PCR extend algorithm)
    while IFS= read -r line; do
        if [[ -n "$line" ]] && [[ ! "$line" =~ ^final_pcr: ]] && [[ ! "$line" =~ ^# ]]; then
            local hash=$(echo "$line" | awk -F: '{print $NF}')
            if [[ ${#hash} -eq 64 ]]; then
                # Simplified PCR extend: hash(current_pcr + measurement)
                pcr_value=$(echo -n "$pcr_value$hash" | sha256sum | awk '{print $1}')
            fi
        fi
    done < "$measurements_file"
    
    echo "$pcr_value"
}

# Main verification function
verify_attestation() {
    local attestation_dir="$1"
    local verification_report="$attestation_dir/verification_report.json"
    
    log "Starting attestation verification for: $attestation_dir"
    
    # Initialize report
    local timestamp=$(date +%s)
    local hostname=$(grep '"hostname"' "$attestation_dir/attestation_info.json" | awk -F'"' '{print $4}')
    
    cat > "$verification_report" << EOF
{
    "verification_timestamp": $timestamp,
    "attester_hostname": "$hostname",
    "overall_result": "PENDING",
    "checks": {
        "quote_signature": "PENDING",
        "measurements": "PENDING",
        "pcr_consistency": "PENDING"
    },
    "failed_measurements": [],
    "warnings": []
}
EOF
    
    local overall_result="PASSED"
    local failed_measurements=()
    local warnings=()
    
    # 1. Verify TPM quote signature
    if verify_quote_signature "$attestation_dir"; then
        sed -i 's/"quote_signature": "PENDING"/"quote_signature": "PASSED"/' "$verification_report"
    else
        sed -i 's/"quote_signature": "PENDING"/"quote_signature": "FAILED"/' "$verification_report"
        overall_result="FAILED"
    fi
    
    # 2. Verify individual measurements
    local measurement_result="PASSED"
    while IFS= read -r measurement; do
        if [[ -n "$measurement" ]] && [[ ! "$measurement" =~ ^# ]] && [[ ! "$measurement" =~ ^final_pcr: ]]; then
            if ! verify_measurement "$measurement"; then
                failed_measurements+=("$measurement")
                measurement_result="FAILED"
                overall_result="FAILED"
            fi
        fi
    done < "$attestation_dir/measurements.txt"
    
    sed -i "s/\"measurements\": \"PENDING\"/\"measurements\": \"$measurement_result\"/" "$verification_report"
    
    # 3. Verify PCR consistency
    local quoted_pcr=$(extract_pcr_from_quote "$attestation_dir" "9")
    local expected_pcr=$(calculate_expected_pcr "$attestation_dir/measurements.txt" "9")
    
    if [ "$quoted_pcr" = "$expected_pcr" ]; then
        sed -i 's/"pcr_consistency": "PENDING"/"pcr_consistency": "PASSED"/' "$verification_report"
        log "PCR consistency check PASSED"
    else
        sed -i 's/"pcr_consistency": "PENDING"/"pcr_consistency": "FAILED"/' "$verification_report"
        warnings+=("PCR mismatch: quoted=$quoted_pcr, expected=$expected_pcr")
        overall_result="FAILED"
        log "PCR consistency check FAILED"
    fi
    
    # Update final report
    sed -i "s/\"overall_result\": \"PENDING\"/\"overall_result\": \"$overall_result\"/" "$verification_report"
    
    # Add failed measurements and warnings to report
    if [ ${#failed_measurements[@]} -gt 0 ]; then
        local failed_json=$(printf '"%s",' "${failed_measurements[@]}")
        failed_json="[${failed_json%,}]"
        sed -i "s/\"failed_measurements\": \[\]/\"failed_measurements\": $failed_json/" "$verification_report"
    fi
    
    if [ ${#warnings[@]} -gt 0 ]; then
        local warnings_json=$(printf '"%s",' "${warnings[@]}")
        warnings_json="[${warnings_json%,}]"
        sed -i "s/\"warnings\": \[\]/\"warnings\": $warnings_json/" "$verification_report"
    fi
    
    log "Verification completed: $overall_result"
    log "Report saved to: $verification_report"
    
    # Return status
    if [ "$overall_result" = "PASSED" ]; then
        return 0
    else
        return 1
    fi
}

# Trust decision for network path attestation
make_trust_decision() {
    local attestation_dir="$1"
    local verification_report="$attestation_dir/verification_report.json"
    
    if [ ! -f "$verification_report" ]; then
        echo "UNTRUSTED: No verification report found"
        return 1
    fi
    
    local overall_result=$(grep '"overall_result"' "$verification_report" | awk -F'"' '{print $4}')
    local hostname=$(grep '"attester_hostname"' "$verification_report" | awk -F'"' '{print $4}')
    
    if [ "$overall_result" = "PASSED" ]; then
        echo "TRUSTED: Node $hostname passed all attestation checks"
        # In real deployment, this would update the trusted topology database
        log "Node $hostname added to trusted topology"
        return 0
    else
        echo "UNTRUSTED: Node $hostname failed attestation verification"
        log "Node $hostname rejected from trusted topology"
        return 1
    fi
}

# Command-line interface
main() {
    local command="${1:-help}"
    
    case "$command" in
        "init")
            log "Initializing verification system..."
            init_reference_db
            ;;
        "add-ref")
            if [ $# -ne 5 ]; then
                echo "Usage: $0 add-ref <component> <subcomponent> <hash> <description>"
                exit 1
            fi
            add_reference_value "$2" "$3" "$4" "$5"
            ;;
        "verify")
            if [ $# -ne 2 ]; then
                echo "Usage: $0 verify <attestation_directory>"
                exit 1
            fi
            verify_attestation "$2"
            ;;
        "trust-decision")
            if [ $# -ne 2 ]; then
                echo "Usage: $0 trust-decision <attestation_directory>"
                exit 1
            fi
            make_trust_decision "$2"
            ;;
        "help"|*)
            cat << 'EOF'
SONiC Attestation Verification System

Usage: verify_attestation.sh <command> [arguments]

Commands:
    init                           Initialize reference values database
    add-ref <comp> <sub> <hash> <desc>  Add reference value to database
    verify <attestation_dir>       Verify attestation evidence
    trust-decision <att_dir>       Make trust decision for network path
    help                          Show this help message

Examples:
    ./verify_attestation.sh init
    ./verify_attestation.sh add-ref kernel version abc123... "Trusted kernel 5.10.0"
    ./verify_attestation.sh verify /var/lib/sonic/measurements/quote_1234567890
    ./verify_attestation.sh trust-decision /var/lib/sonic/measurements/quote_1234567890
EOF
            ;;
    esac
}

main "$@"

