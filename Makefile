#=================================================================
# Makefile for SONiC Attestation System
#=================================================================

# Makefile content (save as separate file)
cat > "$SCRIPT_DIR/../Makefile" << 'EOF'
# SONiC Attestation System Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LIBS = -lcrypto -ljson-c
TARGET = sonic_measure
SOURCE = sonic_measure.c

# Installation directories
INSTALL_DIR = /usr/local/bin
CONFIG_DIR = /etc/sonic/attestation
DATA_DIR = /var/lib/sonic/attestation

# Default target
all: $(TARGET)

# Build the C measurement collector
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Clean build artifacts
clean:
	rm -f $(TARGET)

# Install system
install: $(TARGET)
	sudo ./build_sonic_attestation.sh install

# Uninstall system
uninstall:
	sudo ./build_sonic_attestation.sh uninstall

# Check dependencies
check:
	./build_sonic_attestation.sh check

# Test build
test: $(TARGET)
	./$(TARGET) --help

# Development build with debug symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Static analysis
analyze:
	cppcheck --enable=all $(SOURCE)

# Documentation
docs:
	@echo "Generating documentation..."
	@echo "See README.md for usage instructions"

.PHONY: all clean install uninstall check test debug analyze docs
EOF
