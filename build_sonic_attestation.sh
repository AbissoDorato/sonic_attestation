#!/bin/bash
# SONiC Attestation System - Build and Installation Script
# build_sonic_attestation.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sonic/attestation"
DATA_DIR="/var/lib/sonic/attestation"
LOG_DIR="/var/log/sonic"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check system dependencies
check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    local required_packages=(
        "build-essential"
        "gcc"
        "libssl-dev"
        "libjson-c-dev"
        "swtpm"
        "tpm2-tools"
        "openssl"
        "jq"
    )
    
    for pkg in "${required_packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            missing_deps+=("$pkg")
        fi
    done
    
    if [ ${#missing_deps[@]} -gt 0 ]; then
        log_warn "Missing dependencies: ${missing_deps[*]}"
        log_info "Installing missing dependencies..."
        
        apt-get update
        apt-get install -y "${missing_deps[@]}"
    fi
    
    log_info "All dependencies satisfied"
}

# Build C measurement collector
build_c_collector() {
    log_info "Building C measurement collector..."
    
    local src_file="$SCRIPT_DIR/sonic_measure.c"
    local bin_file="$SCRIPT_DIR/sonic_measure"
    
    if [ ! -f "$src_file" ]; then
        log_error "C source file not found: $src_file"
        return 1
    fi
    
    gcc -o "$bin_file" "$src_file" \
        -lcrypto -ljson-c \
        -Wall -Wextra -O2 \
        -DVERSION="\"1.0.0\""
    
    if [ $? -eq 0 ]; then
        log_info "C measurement collector built successfully"
        chmod +x "$bin_file"
    else
        log_error "Failed to build C measurement collector"
        return 1
    fi
}

# Create directory structure
create_directories() {
    log_info "Creating directory structure..."
    
    local directories=(
        "$CONFIG_DIR"
        "$DATA_DIR"
        "$DATA_DIR/tpm"
        "$DATA_DIR/measurements"
        "$DATA_DIR/trust_tokens"
        "$LOG_DIR"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        log_info "Created directory: $dir"
    done
    
    # Set appropriate permissions
    chmod 700 "$DATA_DIR/tpm"
    chmod 755 "$DATA_DIR/measurements"
    chmod 755 "$DATA_DIR/trust_tokens"
    chmod 755 "$LOG_DIR"
}

# Install scripts and binaries
install_files() {
    log_info "Installing scripts and binaries..."
    
    local files_to_install=(
        "setup_attestation.sh:755"
        "measure_system.sh:755"
        "generate_quote.sh:755"
        "verify_attestation.sh:755"
        "network_trust_manager.sh:755"
        "sonic_measure:755"
    )
    
    for file_info in "${files_to_install[@]}"; do
        local file=$(echo "$file_info" | cut -d: -f1)
        local perm=$(echo "$file_info" | cut -d: -f2)
        
        if [ -f "$SCRIPT_DIR/$file" ]; then
            cp "$SCRIPT_DIR/$file" "$INSTALL_DIR/"
            chmod "$perm" "$INSTALL_DIR/$file"
            log_info "Installed: $INSTALL_DIR/$file"
        else
            log_warn "File not found: $SCRIPT_DIR/$file"
        fi
    done
}

# Create configuration files
create_config_files() {
    log_info "Creating configuration files..."
    
    # Main attestation configuration
    cat > "$CONFIG_DIR/attestation.conf" << 'EOF'
# SONiC Attestation System Configuration

# TPM Configuration
TPM_TYPE="software"
TPM_STATE_DIR="/var/lib/sonic/attestation/tpm"
TPM_SOCKET_PATH="/var/lib/sonic/attestation/tpm/swtpm-sock"

# Measurement Configuration
MEASUREMENTS_DIR="/var/lib/sonic/attestation/measurements"
PCR_NUMBER="9"
HASH_ALGORITHM="sha256"

# Network Configuration
ATTESTATION_PORT="8443"
TRUST_TOKEN_VALIDITY="3600"
MAX_ATTESTATION_AGE="3600"

# Logging Configuration
LOG_LEVEL="INFO"
LOG_FILE="/var/log/sonic/attestation.log"

# Components to measure
MEASURE_FIRMWARE="true"
MEASURE_KERNEL="true"
MEASURE_SONIC_CONFIG="true"
MEASURE_ROUTING="true"
MEASURE_SERVICES="true"
MEASURE_HARDWARE="true"

# Security Settings
REQUIRE_ATTESTATION="true"
TRUSTED_PATH_ONLY="false"
ENABLE_TRUST_TOKENS="true"
EOF

    # Reference values template
    cat > "$CONFIG_DIR/reference_values.conf" << 'EOF'
# SONiC Attestation Reference Values Configuration
# Format: component:subcomponent:expected_hash:description

# Example entries (replace with actual values)
#kernel:version:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456:Linux 5.10.0-sonic
#sonic:config_db:b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567a:default-config
#firmware:bios_version:c3d4e5f6789012345678901234567890abcdef1234567890abcdef1234567ab2:AMI BIOS v2.1.0

# Add your trusted reference values here
EOF

    # Systemd service file
    cat > "/etc/systemd/system/sonic-attestation.service" << 'EOF'
[Unit]
Description=SONiC Attestation Service
After=network.target docker.service
Requires=docker.service
ConditionPathExists=/dev/tpmrm0

[Service]
Type=oneshot
User=root
Environment=TPM2TOOLS_TCTI=device:/dev/tpmrm0
ExecStart=/usr/local/bin/setup_attestation.sh
#ExecStartPost=/usr/local/bin/network_trust_manager.sh daemon
RemainAfterExit=yes
# If network_trust_manager.sh is a daemon that keeps running on its own,
# oneshot + ExecStartPost is fine. If it *doesn't* daemonize, then make
# it the main process with Type=simple and only one ExecStart.

[Install]
WantedBy=multi-user.target
EOF

    log_info "Configuration files created"
}

# Create helper scripts
create_helper_scripts() {
    log_info "Creating helper scripts..."
    
    # Attestation status script
    cat > "$INSTALL_DIR/sonic_attestation_status.sh" << 'EOF'
#!/bin/bash
# SONiC Attestation Status Script

source /etc/sonic/attestation/attestation.conf

echo "SONiC Attestation System Status"
echo "================================"

# Check if swtpm is running
if pgrep -f "swtpm socket" > /dev/null; then
    echo "✓ Software TPM: Running"
else
    echo "✗ Software TPM: Not running"
fi

# Check attestation keys
if [ -f "$TPM_STATE_DIR/ak.ctx" ]; then
    echo "✓ Attestation Key: Present"
else
    echo "✗ Attestation Key: Missing"
fi

# Check recent measurements
if [ -f "$MEASUREMENTS_DIR/measurements.txt" ]; then
    MTIME=$(stat -c %Y "$MEASUREMENTS_DIR/measurements.txt")
    CURRENT=$(date +%s)
    AGE=$((CURRENT - MTIME))
    echo "✓ Last measurement: $(date -d @$MTIME) (${AGE}s ago)"
else
    echo "✗ No measurements found"
fi

# Check trusted topology
TOPOLOGY_DB="/var/lib/sonic/attestation/trusted_topology.json"
if [ -f "$TOPOLOGY_DB" ]; then
    TRUSTED_COUNT=$(grep -c '"trusted"' "$TOPOLOGY_DB" 2>/dev/null || echo "0")
    UNTRUSTED_COUNT=$(grep -c '"untrusted"' "$TOPOLOGY_DB" 2>/dev/null || echo "0")
    echo "✓ Trusted nodes: $TRUSTED_COUNT"
    echo "✓ Untrusted nodes: $UNTRUSTED_COUNT"
else
    echo "✗ Trusted topology database not found"
fi

# Check service status
if systemctl is-active sonic-attestation > /dev/null 2>&1; then
    echo "✓ Attestation service: Active"
else
    echo "✗ Attestation service: Inactive"
fi
EOF

    # Quick measurement script
    cat > "$INSTALL_DIR/sonic_quick_measure.sh" << 'EOF'
#!/bin/bash
# Quick measurement and attestation script

set -euo pipefail

source /etc/sonic/attestation/attestation.conf

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Use C collector if available, otherwise bash
if [ -x "/usr/local/bin/sonic_measure" ]; then
    log "Using C measurement collector..."
    /usr/local/bin/sonic_measure -o "$MEASUREMENTS_DIR/measurements.txt" -j "$MEASUREMENTS_DIR/measurements.json" -l "$LOG_FILE"
else
    log "Using bash measurement collector..."
    /usr/local/bin/measure_system.sh
fi

# Generate quote
NONCE=$(openssl rand -hex 16)
QUOTE_DIR=$(/usr/local/bin/generate_quote.sh "$NONCE")

log "Quick attestation completed"
log "Quote directory: $QUOTE_DIR"
log "Nonce: $NONCE"

echo "$QUOTE_DIR"
EOF

    chmod +x "$INSTALL_DIR/sonic_attestation_status.sh"
    chmod +x "$INSTALL_DIR/sonic_quick_measure.sh"
    
    log_info "Helper scripts created"
}

# Setup log rotation
setup_log_rotation() {
    log_info "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/sonic-attestation" << 'EOF'
/var/log/sonic/attestation*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    maxsize 100M
}
EOF

    log_info "Log rotation configured"
}

# Main installation function
main_install() {
    log_info "Starting SONiC Attestation System installation..."
    
    check_root
    check_dependencies
    build_c_collector
    create_directories
    install_files
    create_config_files
    create_helper_scripts
    setup_log_rotation
    
    # Enable systemd service
    systemctl daemon-reload
    systemctl enable sonic-attestation.service
    
    log_info "Installation completed successfully!"
    echo
    log_info "Next steps:"
    echo "1. Review configuration in $CONFIG_DIR/attestation.conf"
    echo "2. Add reference values to $CONFIG_DIR/reference_values.conf"
    echo "3. Start the service: systemctl start sonic-attestation"
    echo "4. Check status: $INSTALL_DIR/sonic_attestation_status.sh"
    echo "5. Run quick test: $INSTALL_DIR/sonic_quick_measure.sh"
}

# Uninstall function
uninstall() {
    log_info "Uninstalling SONiC Attestation System..."
    
    # Stop service
    systemctl stop sonic-attestation.service 2>/dev/null || true
    systemctl disable sonic-attestation.service 2>/dev/null || true
    
    # Remove files
    local files_to_remove=(
        "$INSTALL_DIR/setup_attestation.sh"
        "$INSTALL_DIR/measure_system.sh"
        "$INSTALL_DIR/generate_quote.sh"
        "$INSTALL_DIR/verify_attestation.sh"
        "$INSTALL_DIR/network_trust_manager.sh"
        "$INSTALL_DIR/sonic_measure"
        "$INSTALL_DIR/sonic_attestation_status.sh"
        "$INSTALL_DIR/sonic_quick_measure.sh"
        "/etc/systemd/system/sonic-attestation.service"
        "/etc/logrotate.d/sonic-attestation"
    )
    
    for file in "${files_to_remove[@]}"; do
        if [ -f "$file" ]; then
            rm "$file"
            log_info "Removed: $file"
        fi
    done
    
    # Optionally remove data directories
    read -p "Remove configuration and data directories? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" "$DATA_DIR"
        log_info "Removed configuration and data directories"
    fi
    
    systemctl daemon-reload
    log_info "Uninstallation completed"
}

# Command line interface
case "${1:-install}" in
    "install")
        main_install
        ;;
    "uninstall")
        check_root
        uninstall
        ;;
    "build")
        build_c_collector
        ;;
    "check")
        check_dependencies
        ;;
    "help"|*)
        cat << 'EOF'
SONiC Attestation System Build and Installation Script

Usage: build_sonic_attestation.sh <command>

Commands:
    install     Full installation (default)
    uninstall   Remove attestation system
    build       Build C measurement collector only
    check       Check system dependencies
    help        Show this help message

Examples:
    ./build_sonic_attestation.sh install
    ./build_sonic_attestation.sh uninstall
    ./build_sonic_attestation.sh build
EOF
        ;;
esac
