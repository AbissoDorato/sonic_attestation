#=================================================================
# network_trust_manager.sh - Network Path Attestation Manager  
#=================================================================

#!/bin/bash
# SONiC Network Trust Manager
# network_trust_manager.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUSTED_TOPOLOGY_DB="/var/lib/sonic/attestation/trusted_topology.json"
TRUST_TOKENS_DIR="/var/lib/sonic/attestation/trust_tokens"
LOG_FILE="/var/log/sonic/network_trust.log"
ATTESTATION_PORT="8443"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Initialize trusted topology database
init_trusted_topology() {
    local db_dir="$(dirname "$TRUSTED_TOPOLOGY_DB")"
    mkdir -p "$db_dir" "$TRUST_TOKENS_DIR"
    
    if [ ! -f "$TRUSTED_TOPOLOGY_DB" ]; then
        log "Creating trusted topology database..."
        cat > "$TRUSTED_TOPOLOGY_DB" << 'EOF'
{
    "last_updated": 0,
    "trusted_nodes": {},
    "trusted_paths": [],
    "untrusted_nodes": {},
    "network_policies": {
        "require_attestation": true,
        "max_attestation_age": 3600,
        "trusted_path_only": false
    }
}
EOF
        log "Trusted topology database initialized"
    fi
}

# Update node trust status
update_node_trust() {
    local hostname="$1"
    local status="$2"
    local attestation_data="$3"
    local timestamp=$(date +%s)
    
    log "Updating trust status for $hostname: $status"
    
    # Create temporary file for JSON manipulation
    local temp_file=$(mktemp)
    
    # Use a simple approach to update JSON (in production, use proper JSON parser)
    if [ "$status" = "TRUSTED" ]; then
        # Add to trusted nodes, remove from untrusted
        cat "$TRUSTED_TOPOLOGY_DB" | \
        sed "s/\"trusted_nodes\": {/\"trusted_nodes\": {\"$hostname\": {\"last_attestation\": $timestamp, \"status\": \"trusted\", \"data\": \"$attestation_data\"},/" | \
        sed "/\"$hostname\".*untrusted/d" > "$temp_file"
    else
        # Add to untrusted nodes, remove from trusted
        cat "$TRUSTED_TOPOLOGY_DB" | \
        sed "s/\"untrusted_nodes\": {/\"untrusted_nodes\": {\"$hostname\": {\"last_check\": $timestamp, \"status\": \"untrusted\", \"reason\": \"$attestation_data\"},/" | \
        sed "/\"$hostname\".*trusted/d" > "$temp_file"
    fi
    
    # Update last_updated timestamp
    sed -i "s/\"last_updated\": [0-9]*/\"last_updated\": $timestamp/" "$temp_file"
    
    mv "$temp_file" "$TRUSTED_TOPOLOGY_DB"
    log "Node $hostname trust status updated to $status"
}

# Check if node is trusted
is_node_trusted() {
    local hostname="$1"
    local max_age="${2:-3600}"  # Default 1 hour
    local current_time=$(date +%s)
    
    # Extract node info from JSON (simplified parsing)
    local node_info=$(grep "\"$hostname\"" "$TRUSTED_TOPOLOGY_DB" || echo "")
    
    if [[ "$node_info" =~ \"trusted\" ]]; then
        # Extract timestamp
        local last_attestation=$(echo "$node_info" | grep -o '"last_attestation": [0-9]*' | awk '{print $2}')
        local age=$((current_time - last_attestation))
        
        if [ "$age" -le "$max_age" ]; then
            echo "TRUSTED"
            return 0
        else
            log "Node $hostname attestation expired (age: ${age}s, max: ${max_age}s)"
            echo "EXPIRED"
            return 1
        fi
    else
        echo "UNTRUSTED"
        return 1
    fi
}

# Generate trust token for node
generate_trust_token() {
    local hostname="$1"
    local validity_period="${2:-3600}"
    local timestamp=$(date +%s)
    local expiry=$((timestamp + validity_period))
    
    # Create trust token directory for this node
    local token_dir="$TRUST_TOKENS_DIR/$hostname"
    mkdir -p "$token_dir"
    
    # Generate token data
    local token_data="hostname:$hostname,issued:$timestamp,expires:$expiry,nonce:$(openssl rand -hex 16)"
    
    # Sign token with node's attestation key (simplified - in real deployment use proper PKI)
    echo "$token_data" > "$token_dir/trust_token.data"
    echo "$token_data" | sha256sum | awk '{print $1}' > "$token_dir/trust_token.sig"
    
    log "Generated trust token for $hostname (expires: $(date -d @$expiry))"
    echo "$token_dir/trust_token.data"
}

# Validate trust token
validate_trust_token() {
    local token_file="$1"
    local current_time=$(date +%s)
    
    if [ ! -f "$token_file" ]; then
        echo "INVALID: Token file not found"
        return 1
    fi
    
    local token_data=$(cat "$token_file")
    local hostname=$(echo "$token_data" | grep -o 'hostname:[^,]*' | cut -d: -f2)
    local expires=$(echo "$token_data" | grep -o 'expires:[^,]*' | cut -d: -f2)
    
    if [ "$current_time" -gt "$expires" ]; then
        echo "EXPIRED: Token expired at $(date -d @$expires)"
        return 1
    fi
    
    # Verify signature (simplified)
    local sig_file="${token_file%.data}.sig"
    if [ -f "$sig_file" ]; then
        local expected_sig=$(cat "$sig_file")
        local actual_sig=$(echo "$token_data" | sha256sum | awk '{print $1}')
        
        if [ "$expected_sig" = "$actual_sig" ]; then
            echo "VALID: Token for $hostname valid until $(date -d @$expires)"
            return 0
        else
            echo "INVALID: Token signature mismatch"
            return 1
        fi
    else
        echo "INVALID: Token signature not found"
        return 1
    fi
}

# Calculate trusted paths between nodes
calculate_trusted_paths() {
    local source="$1"
    local destination="$2"
    
    log "Calculating trusted paths from $source to $destination"
    
    # Simple path calculation (in real deployment, integrate with routing protocols)
    # For now, just check if both nodes are trusted
    local source_trust=$(is_node_trusted "$source" && echo "TRUSTED" || echo "UNTRUSTED")
    local dest_trust=$(is_node_trusted "$destination" && echo "TRUSTED" || echo "UNTRUSTED")
    
    if [ "$source_trust" = "TRUSTED" ] && [ "$dest_trust" = "TRUSTED" ]; then
        echo "TRUSTED_PATH: Direct path $source -> $destination"
        return 0
    else
        echo "UNTRUSTED_PATH: Cannot establish trusted path"
        return 1
    fi
}

# Process incoming attestation request
handle_attestation_request() {
    local requesting_node="$1"
    local nonce="$2"
    
    log "Processing attestation request from $requesting_node with nonce $nonce"
    
    # Generate measurements and quote
    "$SCRIPT_DIR/measure_system.sh"
    local quote_dir=$("$SCRIPT_DIR/generate_quote.sh" "$nonce")
    
    # Send quote back to requesting node (simplified - use proper network protocol)
    log "Attestation evidence generated in $quote_dir"
    echo "$quote_dir"
}

# Request attestation from remote node
request_node_attestation() {
    local target_node="$1"
    local nonce=$(openssl rand -hex 16)
    
    log "Requesting attestation from $target_node"
    
    # In real deployment, this would be a network call
    # For simulation, we'll assume the response is available locally
    echo "Sent attestation request to $target_node with nonce $nonce"
    echo "Response would contain: quote, signature, measurements"
}

# Network policy enforcement
enforce_network_policy() {
    local policy_name="$1"
    local source_node="$2"
    local dest_node="$3"
    local packet_info="$4"
    
    log "Enforcing policy '$policy_name' for $source_node -> $dest_node"
    
    case "$policy_name" in
        "trusted_path_only")
            if calculate_trusted_paths "$source_node" "$dest_node" >/dev/null; then
                echo "ALLOW: Trusted path available"
                return 0
            else
                echo "DENY: No trusted path available"
                return 1
            fi
            ;;
        "require_attestation")
            local source_trust=$(is_node_trusted "$source_node" && echo "TRUSTED" || echo "UNTRUSTED")
            local dest_trust=$(is_node_trusted "$dest_node" && echo "TRUSTED" || echo "UNTRUSTED")
            
            if [ "$source_trust" = "TRUSTED" ] && [ "$dest_trust" = "TRUSTED" ]; then
                echo "ALLOW: Both nodes attested"
                return 0
            else
                echo "DENY: Node attestation required"
                return 1
            fi
            ;;
        *)
            echo "ALLOW: Unknown policy, defaulting to allow"
            return 0
            ;;
    esac
}

# Start attestation daemon
start_attestation_daemon() {
    log "Starting SONiC attestation daemon on port $ATTESTATION_PORT"
    
    # Simple HTTP server simulation (in real deployment, use proper server)
    while true; do
        log "Attestation daemon listening..."
        
        # Check for expired attestations
        cleanup_expired_attestations
        
        # Sleep and repeat
        sleep 60
    done
}

# Cleanup expired attestations
cleanup_expired_attestations() {
    local current_time=$(date +%s)
    local max_age=3600
    
    # Parse trusted nodes and check ages (simplified)
    grep '"last_attestation"' "$TRUSTED_TOPOLOGY_DB" | while read -r line; do
        local hostname=$(echo "$line" | grep -o '"[^"]*":' | head -1 | tr -d '":')
        local timestamp=$(echo "$line" | grep -o '"last_attestation": [0-9]*' | awk '{print $2}')
        local age=$((current_time - timestamp))
        
        if [ "$age" -gt "$max_age" ]; then
            log "Removing expired attestation for $hostname (age: ${age}s)"
            update_node_trust "$hostname" "EXPIRED" "attestation_expired"
        fi
    done
}

# Command-line interface
main() {
    local command="${1:-help}"
    
    case "$command" in
        "init")
            log "Initializing network trust manager..."
            init_trusted_topology
            ;;
        "update-trust")
            if [ $# -ne 4 ]; then
                echo "Usage: $0 update-trust <hostname> <status> <data>"
                exit 1
            fi
            update_node_trust "$2" "$3" "$4"
            ;;
        "check-trust")
            if [ $# -lt 2 ]; then
                echo "Usage: $0 check-trust <hostname> [max_age_seconds]"
                exit 1
            fi
            is_node_trusted "$2" "${3:-3600}"
            ;;
        "generate-token")
            if [ $# -lt 2 ]; then
                echo "Usage: $0 generate-token <hostname> [validity_seconds]"
                exit 1
            fi
            generate_trust_token "$2" "${3:-3600}"
            ;;
        "validate-token")
            if [ $# -ne 2 ]; then
                echo "Usage: $0 validate-token <token_file>"
                exit 1
            fi
            validate_trust_token "$2"
            ;;
        "calc-paths")
            if [ $# -ne 3 ]; then
                echo "Usage: $0 calc-paths <source> <destination>"
                exit 1
            fi
            calculate_trusted_paths "$2" "$3"
            ;;
        "request-attestation")
            if [ $# -ne 2 ]; then
                echo "Usage: $0 request-attestation <target_node>"
                exit 1
            fi
            request_node_attestation "$2"
            ;;
        "enforce-policy")
            if [ $# -ne 5 ]; then
                echo "Usage: $0 enforce-policy <policy> <source> <dest> <packet_info>"
                exit 1
            fi
            enforce_network_policy "$2" "$3" "$4" "$5"
            ;;
        "daemon")
            start_attestation_daemon
            ;;
        "cleanup")
            cleanup_expired_attestations
            ;;
        "status")
            log "Network Trust Manager Status:"
            echo "Trusted topology database: $TRUSTED_TOPOLOGY_DB"
            echo "Trust tokens directory: $TRUST_TOKENS_DIR"
            echo "Log file: $LOG_FILE"
            if [ -f "$TRUSTED_TOPOLOGY_DB" ]; then
                echo "Last updated: $(grep '"last_updated"' "$TRUSTED_TOPOLOGY_DB" | awk '{print $2}' | tr -d ',')"
                echo "Trusted nodes: $(grep -c '"trusted"' "$TRUSTED_TOPOLOGY_DB" 2>/dev/null || echo "0")"
                echo "Untrusted nodes: $(grep -c '"untrusted"' "$TRUSTED_TOPOLOGY_DB" 2>/dev/null || echo "0")"
            fi
            ;;
        "help"|*)
            cat << 'EOF'
SONiC Network Trust Manager

Usage: network_trust_manager.sh <command> [arguments]

Commands:
    init                                Initialize trusted topology database
    update-trust <host> <status> <data>  Update node trust status
    check-trust <host> [max_age]        Check if node is trusted
    generate-token <host> [validity]    Generate trust token for node
    validate-token <token_file>         Validate trust token
    calc-paths <source> <dest>          Calculate trusted paths
    request-attestation <node>          Request attestation from node
    enforce-policy <policy> <src> <dst> <info>  Enforce network policy
    daemon                              Start attestation daemon
    cleanup                             Clean up expired attestations
    status                              Show system status
    help                               Show this help message

Examples:
    ./network_trust_manager.sh init
    ./network_trust_manager.sh update-trust switch01 TRUSTED /path/to/attestation
    ./network_trust_manager.sh check-trust switch01 3600
    ./network_trust_manager.sh generate-token switch01 7200
    ./network_trust_manager.sh enforce-policy trusted_path_only switch01 switch02 "tcp:80"
EOF
            ;;
    esac
}

main "$@"
