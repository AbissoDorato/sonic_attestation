# SONiC Attestation System Documentation

## Overview

The SONiC Attestation System provides network path attestation capabilities for SONiC OS, ensuring that packets traverse only through nodes whose configurations and software states are verifiably trustworthy. This system implements the IETF RATS (Remote Attestation Procedures) model using software TPM emulation.

## Architecture

### Components

1. **Attester (SONiC node)**
   - Performs system measurements
   - Extends measurements into TPM PCRs
   - Generates signed TPM quotes

2. **Verifier (remote system)**
   - Validates attestation evidence
   - Compares measurements with reference values
   - Makes trust decisions

3. **Relying Party (network orchestrator)**
   - Builds trusted topology
   - Enforces network policies

### Key Features

- **Software TPM Integration**: Uses swtpm for TPM 2.0 emulation
- **Comprehensive Measurement**: Covers firmware, kernel, SONiC config, routing tables, and services
- **High-Performance C Collector**: Optional C-based measurement tool for better performance
- **Network Trust Management**: Manages trusted topology and path attestation
- **Reference Value Database**: Maintains known-good measurements for verification

## Installation

### Prerequisites

- SONiC OS running on target device
- Root access for installation
- Internet connection for dependency installation

### System Requirements

- Ubuntu/Debian-based system
- Docker support
- At least 1GB free disk space
- Network connectivity for attestation requests

### Required Packages

```bash
# Automatically installed by build script
build-essential gcc libssl-dev libjson-c-dev
swtpm tpm2-tools docker.io openssl jq
```

### Installation Steps

1. **Download and extract the attestation system:**
```bash
# Extract all scripts to a directory
cd /opt
mkdir sonic-attestation
cd sonic-attestation
```

2. **Run the installation script:**
```bash
sudo ./build_sonic_attestation.sh install
```

3. **Verify installation:**
```bash
sonic_attestation_status.sh
```

## Configuration

### Main Configuration File

Edit `/etc/sonic/attestation/attestation.conf`:

```bash
# TPM Configuration
TPM_TYPE="software"
TPM_STATE_DIR="/var/lib/sonic/attestation/tpm"

# Measurement Configuration
MEASUREMENTS_DIR="/var/lib/sonic/attestation/measurements"
PCR_NUMBER="9"

# Network Configuration
ATTESTATION_PORT="8443"
TRUST_TOKEN_VALIDITY="3600"

# Components to measure
MEASURE_FIRMWARE="true"
MEASURE_KERNEL="true"
MEASURE_SONIC_CONFIG="true"
MEASURE_ROUTING="true"
MEASURE_SERVICES="true"
MEASURE_HARDWARE="true"
```

### Reference Values

Add trusted reference values to `/etc/sonic/attestation/reference_values.conf`:

```bash
# Format: component:subcomponent:expected_hash:description
kernel:version:a1b2c3d4e5f6....:Linux 5.10.0-sonic
sonic:config_db:b2c3d4e5f67....:default-config
firmware:bios_version:c3d4e5f6....:AMI BIOS v2.1.0
```

## Usage

### Basic Operations

#### 1. System Setup
```bash
# Initialize the attestation system
sudo setup_attestation.sh
```

#### 2. Perform Measurements
```bash
# Using bash script
sudo measure_system.sh

# Using C collector (faster)
sudo sonic_measure -o /var/lib/sonic/attestation/measurements/measurements.txt \
                   -j /var/lib/sonic/attestation/measurements/measurements.json
```

#### 3. Generate Attestation Quote
```bash
# Generate quote with random nonce
sudo generate_quote.sh

# Generate quote with specific nonce
sudo generate_quote.sh "deadbeef1234567890abcdef"
```

#### 4. Verify Attestation
```bash
# Initialize reference database
sudo verify_attestation.sh init

# Add reference values
sudo verify_attestation.sh add-ref kernel version abc123... "Trusted kernel"

# Verify attestation evidence
sudo verify_attestation.sh verify /var/lib/sonic/attestation/measurements/quote_1234567890

# Make trust decision
sudo verify_attestation.sh trust-decision /var/lib/sonic/attestation/measurements/quote_1234567890
```

### Network Trust Management

#### 1. Initialize Trusted Topology
```bash
sudo network_trust_manager.sh init
```

#### 2. Update Node Trust Status
```bash
# Mark node as trusted
sudo network_trust_manager.sh update-trust switch01 TRUSTED /path/to/attestation

# Mark node as untrusted
sudo network_trust_manager.sh update-trust switch02 UNTRUSTED "failed_verification"
```

#### 3. Check Node Trust
```bash
# Check if node is trusted
network_trust_manager.sh check-trust switch01

# Check with specific age limit (seconds)
network_trust_manager.sh check-trust switch01 3600
```

#### 4. Generate Trust Tokens
```bash
# Generate token for trusted node
network_trust_manager.sh generate-token switch01 7200

# Validate existing token
network_trust_manager.sh validate-token /path/to/token/file
```

#### 5. Enforce Network Policies
```bash
# Enforce trusted-path-only policy
network_trust_manager.sh enforce-policy trusted_path_only switch01 switch02 "tcp:80"

# Enforce attestation requirement
network_trust_manager.sh enforce-policy require_attestation switch01 switch02 "any"
```

### Service Management

#### Start Attestation Service
```bash
sudo systemctl start sonic-attestation
sudo systemctl enable sonic-attestation
```

#### Check Service Status
```bash
systemctl status sonic-attestation
sonic_attestation_status.sh
```

#### View Logs
```bash
tail -f /var/log/sonic/attestation.log
journalctl -u sonic-attestation -f
```

## API Reference

### C Measurement Collector

```bash
# Basic usage
sonic_measure [options]

# Options:
-o, --output <file>      Output file path (default: measurements.txt)
-j, --json <file>        JSON output file path  
-l, --log <file>         Log file path
-v, --verbose            Enable verbose logging
-q, --quiet              Quiet mode (errors only)
-c, --components <list>  Comma-separated component list
-h, --help               Show help message

# Examples:
sonic_measure -o /tmp/measurements.txt -j /tmp/measurements.json
sonic_measure -c firmware,kernel,sonic -v
sonic_measure --quiet --output /var/lib/sonic/measurements.txt
```

### Bash Script APIs

#### setup_attestation.sh
- Initializes directories and TPM
- Creates attestation keys
- Sets up system environment

#### measure_system.sh
- Collects system measurements
- Extends measurements into TPM PCRs
- Saves measurement data

#### generate_quote.sh
```bash
generate_quote.sh [nonce] [output_directory]
```

#### verify_attestation.sh
```bash
verify_attestation.sh <command> [arguments]

Commands:
- init: Initialize reference database
- add-ref <component> <subcomponent> <hash> <description>
- verify <attestation_directory>
- trust-decision <attestation_directory>
```

#### network_trust_manager.sh
```bash
network_trust_manager.sh <command> [arguments]

Commands:
- init: Initialize trusted topology
- update-trust <hostname> <status> <data>
- check-trust <hostname> [max_age]
- generate-token <hostname> [validity]
- validate-token <token_file>
- calc-paths <source> <destination>
- enforce-policy <policy> <source> <dest> <info>
- daemon: Start attestation daemon
```

## Measurement Scope

### System Components Measured

1. **Firmware/BIOS**
   - BIOS version and vendor
   - BIOS date
   - UEFI configuration

2. **Kernel**
   - Kernel version and build
   - Boot parameters
   - Loaded modules
   - Kernel configuration

3. **SONiC Configuration**
   - config_db.json
   - sonic_version.yml
   - FRR configuration
   - Additional config files

4. **Routing and Forwarding**
   - Kernel routing tables
   - IPv6 routes
   - ARP/neighbor tables
   - FRR running config
   - BGP state

5. **Services and Containers**
   - Running Docker containers
   - Container images
   - Redis database state
   - SystemD services

6. **Hardware**
   - CPU information
   - Memory configuration
   - PCI devices
   - Network interfaces

## Security Considerations

### TPM Security

- Uses software TPM (swtpm) for MVP
- Production deployment should use hardware TPM
- TPM state directory has restricted permissions (700)
- Attestation keys are protected by TPM

### Network Security

- Attestation traffic should use TLS
- Trust tokens have expiration times
- Nonces prevent replay attacks
- Reference values must be securely managed

### Measurement Integrity

- SHA-256 used for all measurements
- PCR extensions provide cryptographic accumulation
- Measurements include timestamps
- Critical files are monitored for changes

## Troubleshooting

### Common Issues

#### TPM Not Starting
```bash
# Check swtpm installation
which swtpm

# Check TPM state directory permissions
ls -la /var/lib/sonic/attestation/tpm/

# Start TPM manually
sudo setup_attestation.sh
```

#### Measurement Failures
```bash
# Check file permissions
ls -la /etc/sonic/
docker ps

# Run with verbose logging
sonic_measure -v -l /tmp/debug.log

# Check system dependencies
./build_sonic_attestation.sh check
```

#### Verification Failures
```bash
# Check reference values database
cat /var/lib/sonic/attestation/reference_values.db

# Run verification with debug
sudo verify_attestation.sh verify /path/to/attestation 2>&1 | tee debug.log
```

### Log Analysis

```bash
# Check main log
tail -f /var/log/sonic/attestation.log

# Check system logs
journalctl -u sonic-attestation

# Enable debug logging
# Edit /etc/sonic/attestation/attestation.conf
LOG_LEVEL="DEBUG"
```

## Testing

### Run Test Suite
```bash
# Basic tests
sudo ./test_sonic_attestation.sh

# Include performance tests
sudo ./test_sonic_attestation.sh --performance
```

### Manual Testing

#### Test Measurement Collection
```bash
# Quick measurement test
sonic_quick_measure.sh

# Test specific components
sonic_measure -c kernel,sonic -v
```

#### Test TPM Operations
```bash
# Check TPM status
tpm2_pcrread sha256:9

# Test quote generation
generate_quote.sh test_nonce
```

## Performance Optimization

### C vs Bash Performance

- C collector: ~2-5 seconds for full measurement
- Bash scripts: ~10-30 seconds for full measurement
- Use C collector for production deployments

### Measurement Optimization

- Disable unused components in config
- Use hardware TPM for better performance
- Cache static measurements when possible
- Implement incremental measurements

## Integration with SONiC

### Systemd Integration

The system integrates with systemd for automatic startup:

```bash
# Service status
systemctl status sonic-attestation

# Service logs
journalctl -u sonic-attestation
```

### Docker Integration

- Monitors SONiC container states
- Measures container images and configurations
- Tracks Redis database state

### Configuration Integration

- Reads SONiC configuration files
- Monitors configuration changes
- Integrates with FRR routing

## Future Enhancements

### Planned Features

1. **Hardware TPM Support**
   - Replace swtpm with hardware TPM
   - Better security guarantees
   - Hardware-rooted trust

2. **Continuous Monitoring**
   - Real-time measurement updates
   - Configuration change detection
   - Automated re-attestation

3. **Network Protocol Integration**
   - NETCONF/RESTCONF APIs
   - gRPC attestation services
   - Integration with network controllers

4. **Advanced Policies**
   - Fine-grained trust policies
   - Risk-based decisions
   - Machine learning for anomaly detection

## Support

### Documentation
- Man pages: `man sonic_measure`
- Built-in help: `sonic_measure --help`
- Configuration examples in `/etc/sonic/attestation/`

### Logging
- Main log: `/var/log/sonic/attestation.log`
- Debug logs available with verbose mode
- Structured JSON logs for automated processing

### Community
- Report issues via SONiC community channels
- Contribute improvements via pull requests
- Share reference values and configurations

## Conclusion

The SONiC Attestation System provides a robust foundation for network path attestation in SONiC environments. By combining software TPM technology with comprehensive system measurement, it enables verification of network device trustworthiness and supports secure network path establishment.

For production deployments, consider upgrading to hardware TPM and implementing continuous monitoring for enhanced security posture.
