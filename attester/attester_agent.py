#!/usr/bin/env python3
import socket
import struct
import json
import base64
import os
import sys
import time
import subprocess
import tempfile
import yaml
import hashlib
from pathlib import Path
from datetime import datetime
import threading
import signal

# Configuration
AGENT_HOST = '0.0.0.0'  # Listen on all interfaces
AGENT_PORT = 8087       # Default agent port
BUFFER_SIZE = 8192
MAX_CLIENTS = 5

# TPM/Quote generation configuration
QUOTE_SCRIPT = os.environ.get("QUOTE_SCRIPT", "/usr/local/bin/generate_quote.sh")
OUTDIR_BASE = os.environ.get("ATTESTATION_OUTDIR", "/home/admin/attester/quotes")
DEFAULT_PCRS = os.environ.get("PCRS", "13")
HALG = os.environ.get("HALG", "sha256")


class Command:
    PERFORM_ATTESTATION = 0x01
    GET_AK_PUBKEY = 0x02

class AttestationAgent:
    def __init__(self, host=AGENT_HOST, port=AGENT_PORT):
        self.host = host
        self.port = port
        self.running = True
        self.server_socket = None
        
    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[AGENT] [{timestamp}] {message}")

    def _recv_all(self, sock, n):
        """Helper function to receive 'n' bytes from socket."""
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def _send_response(self, sock, response_data):
        """Send a JSON response back to the client."""
        try:
            json_data = json.dumps(response_data).encode('utf-8')
            message = struct.pack('<I', len(json_data)) + json_data
            sock.sendall(message)
            return True
        except Exception as e:
            self.log(f"Failed to send response: {e}")
            return False

    def _run_quote_generation(self, nonce_hex, pcrs, halg):
        """Run the quote generation script and return the output directory."""
        try:
            # Create timestamped output directory
            #ts = time.strftime("%Y%m%d_%H%M%S")
            outdir = Path(OUTDIR_BASE) 
            outdir.mkdir(parents=True, exist_ok=True)
            
            # Build environment for the quote script
            env = os.environ.copy()
            env.update({
                'PCR_NUMBER': str(pcrs),
                'HALG': halg
            })
            
            # Run the quote generation script
            cmd = [QUOTE_SCRIPT,"-n",nonce_hex,"-d", str(outdir)]
            self.log(f"Running: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, env=env, check=True, 
                                  capture_output=True, text=True)
            
            # Verify expected files exist
            expected_files = ["quote.attest", "quote.sig", "nonce.hex", "pcrread.txt", "pcrs.bin"]
            subdirs = [d for d in Path(outdir).iterdir() if d.is_dir()]
            if not subdirs:
                raise FileNotFoundError(f"No subdirectories created in {outdir}")
            # Pick the most recently modified
            final_outdir = max(subdirs, key=lambda d: d.stat().st_mtime)
            
            for f in expected_files:
                if not (final_outdir / f).exists():
                    raise FileNotFoundError(f"Expected file {f} not found in {final_outdir}")
            
    
            self.log(f"Quote generation successful: {final_outdir}")
            return final_outdir
            
        except subprocess.CalledProcessError as e:
            self.log(f"Quote generation failed: {e}")
            self.log(f"stdout: {e.stdout}")
            self.log(f"stderr: {e.stderr}")
            return None
        except Exception as e:
            self.log(f"Quote generation error: {e}")
            return None

    def _get_ak_pubkey(self):
        """Get the AK public key."""
        try:
            # Try to get AK from a standard location or generate it
            ak_paths = [
                "/var/lib/sonic/attestation/ak.pub",
                "/etc/sonic/attestation/ak.pub",
                "/tmp/ak.pub"
            ]
            
            # Check if AK exists in standard locations
            for ak_path in ak_paths:
                if Path(ak_path).exists():
                    with open(ak_path, 'rb') as f:
                        return f.read()
            
            # If no AK found, try to generate one using the quote script
            self.log("No existing AK found, attempting to generate...")
            
            # Create temp directory for AK generation
            with tempfile.TemporaryDirectory() as tmpdir:
                # Run quote script to generate AK (some scripts create AK as side effect)
                env = os.environ.copy()
                env.update({
                    'PCR_NUMBER': DEFAULT_PCRS,
                    'HALG': HALG
                })
                
                # Try to run a dummy quote to generate AK
                dummy_nonce = "0" * 40  # 20 bytes in hex
                cmd = [QUOTE_SCRIPT, "quote", dummy_nonce, tmpdir]
                
                try:
                    subprocess.run(cmd, env=env, check=True, 
                                 capture_output=True, text=True, timeout=30)
                    
                    # Check if AK was generated
                    ak_file = Path(tmpdir) / "ak.pub"
                    if ak_file.exists():
                        ak_data = ak_file.read_bytes()
                        # Save it for future use
                        ak_save_path = Path("/var/lib/sonic/attestation/ak.pub")
                        ak_save_path.parent.mkdir(parents=True, exist_ok=True)
                        ak_save_path.write_bytes(ak_data)
                        self.log(f"AK generated and saved to {ak_save_path}")
                        return ak_data
                        
                except subprocess.TimeoutExpired:
                    self.log("AK generation timed out")
                except subprocess.CalledProcessError as e:
                    self.log(f"AK generation failed: {e}")
            
            # If all else fails, return None
            self.log("Could not obtain AK public key")
            return None
            
        except Exception as e:
            self.log(f"Error getting AK public key: {e}")
            return None
        
    def _get_tss_id(self):
        """Retrieve the ak.tss.sha256 files if available, else call the script to generate them"""
        try:
            tss_paths = ["/var/lib/sonic/attestation/ak.tss.sha256",
                        "/etc/sonic/attestation/ak.tss.sha256",
                        "/tmp/ak.tss.sha256"]
            
            # First try to find existing TSS ID file
            for tss_path in tss_paths:
                if Path(tss_path).exists():
                    with open(tss_path, 'rb') as f:
                        return f.read().strip()
            
            # If not found, generate it using get_id.sh
            self.log("No existing TSS ID found, generating new one...")
            get_id_script = "/usr/local/bin/get_id.sh"
            
            if not Path(get_id_script).exists():
                self.log(f"Error: {get_id_script} not found")
                return None
                
            try:
                # Run get_id.sh script
                result = subprocess.run([get_id_script], 
                                    capture_output=True,
                                    check=True)
                
                # Check if file was generated
                default_path = "/var/lib/sonic/attestation/ak.tss.sha256"
                if Path(default_path).exists():
                    with open(default_path, 'rb') as f:
                        return f.read()
                else:
                    self.log("TSS ID file not generated")
                    return None
                    
            except subprocess.CalledProcessError as e:
                self.log(f"Error running get_id.sh: {e}")
                self.log(f"stdout: {e.stdout}")
                self.log(f"stderr: {e.stderr}")
                return None
                
        except Exception as e:
            self.log(f"Error getting TSS ID: {e}")
            return None

    def _load_file_safe(self, filepath, binary=False):
        """Safely load a file, returning None if it doesn't exist."""
        try:
            path = Path(filepath)
            if not path.exists():
                return None
            
            if binary:
                return path.read_bytes()
            else:
                return path.read_text().strip()
        except Exception as e:
            self.log(f"Error loading file {filepath}: {e}")
            return None

    def _create_quote_metadata(self, outdir):
        """Create additional metadata about the quote/system state."""
        metadata = {
            "timestamp": datetime.now().isoformat(),
            "measurements": {}
        }
        
        try:
            # Add CONFIG_DB checksum if available
            config_paths = [
                "/etc/sonic/config_db.json",
                "/var/lib/sonic/config_db.json"
            ]
            
            for config_path in config_paths:
                if Path(config_path).exists():
                    with open(config_path, 'rb') as f:
                        config_hash = hashlib.sha256(f.read()).hexdigest()
                        metadata["measurements"]["CONFIG_DB_SHA256"] = config_hash
                        break
            
            # Add system info
            metadata["system"] = {
                "hostname": os.uname().nodename,
                "kernel": os.uname().release
            }
            
        except Exception as e:
            self.log(f"Error creating metadata: {e}")
        
        return metadata

    def handle_get_ak_pubkey(self, request_data):
        """Handle GET_AK_PUBKEY command."""
        node_id = request_data.get("node_id", "unknown")
        self.log(f"AK public key requested for node: {node_id}")
        
        ak_data = self._get_ak_pubkey()
        if ak_data is None:
            return {"error": "Could not obtain AK public key"}
        
        response = {
            "node_id": node_id,
            "ak_pub_b64": base64.b64encode(ak_data).decode('utf-8'),
            "timestamp": datetime.now().isoformat()
        }
        
        self.log(f"Returning AK public key ({len(ak_data)} bytes)")
        return response

    def handle_perform_attestation(self, request_data):
        """Handle PERFORM_ATTESTATION command."""
        node_id = request_data.get("node_id", "unknown")
        nonce_hex = request_data.get("nonce_hex", "")
        pcrs = request_data.get("pcrs", DEFAULT_PCRS)
        halg = request_data.get("halg", HALG)
        
        self.log(f"Attestation requested for node: {node_id}")
        self.log(f"Nonce: {nonce_hex}")
        self.log(f"PCRs: {pcrs}, Hash algorithm: {halg}")
        
        if not nonce_hex:
            return {"error": "No nonce provided"}
        
        # Generate the quote
        outdir = self._run_quote_generation(nonce_hex, pcrs, halg)
        if outdir is None:
            return {"error": "Quote generation failed"}
        
        try:
            # Load all the quote artifacts
            quote_msg = self._load_file_safe(outdir / "quote.attest", binary=True)
            quote_sig = self._load_file_safe(outdir / "quote.sig", binary=True)
            pcrs_bin = self._load_file_safe(outdir / "pcrs.bin", binary=True)
            pcrs_yaml = self._load_file_safe(outdir / "pcrread.txt")
            nonce_echo = self._load_file_safe(outdir / "nonce.hex")
            ak_pub = self._get_ak_pubkey()
            
            ak_tss = self._get_tss_id()
            
            # Create metadata
            metadata = self._create_quote_metadata(outdir)
            
            # Build response
            response = {
                "node_id": node_id,
                "timestamp": datetime.now().isoformat(),
                "nonce_hex": nonce_echo or nonce_hex,  # Echo back the nonce
                "pcrs": pcrs,
                "halg": halg
            }
            
            # Add binary data as base64
            
            if quote_msg:
                response["quote_msg_b64"] = base64.b64encode(quote_msg).decode('utf-8')
            
            if quote_sig:
                response["quote_sig_b64"] = base64.b64encode(quote_sig).decode('utf-8')
            
            if pcrs_bin:
                response["pcrs_bin_b64"] = base64.b64encode(pcrs_bin).decode('utf-8')
            else:
                self.log("Warning: pcrs.bin not found or empty")
            
            if ak_pub:
                response["ak_pub_b64"] = base64.b64encode(ak_pub).decode('utf-8')
                
            if ak_tss:
                response["ak_tss_sha256"] = ak_tss.decode('utf-8')
            else:
                self.log("Warning: ak.tss.sha256 not found or empty")
            
            # Add text data
            if pcrs_yaml:
                response["pcrs_yaml"] = pcrs_yaml
            
            response["quote_meta"] = metadata
            
            self.log(f"Attestation response prepared ({len(json.dumps(response))} bytes)")
            return response
            
        except Exception as e:
            self.log(f"Error preparing attestation response: {e}")
            return {"error": f"Failed to prepare response: {str(e)}"}
        
        finally:
            # Optionally clean up the output directory
            # shutil.rmtree(outdir, ignore_errors=True)
            pass

    def handle_client_request(self, sock, addr):
        """Handle a single client request."""
        try:
            self.log(f"Client connected: {addr}")
            
            # Receive command and payload length
            header = self._recv_all(sock, 5)  # 1 byte command + 4 bytes length
            if not header:
                self.log(f"Client {addr} disconnected before sending command")
                return
            
            command, payload_len = struct.unpack('<BI', header)
            self.log(f"Received command: 0x{command:02x}, payload length: {payload_len}")
            
            # Receive payload
            if payload_len > 0:
                payload_data = self._recv_all(sock, payload_len)
                if not payload_data:
                    self.log(f"Client {addr} disconnected while sending payload")
                    return
                
                try:
                    request_data = json.loads(payload_data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    self.log(f"Invalid JSON from {addr}: {e}")
                    self._send_response(sock, {"error": "Invalid JSON"})
                    return
            else:
                request_data = {}
            
            # Handle the command
            if command == Command.GET_AK_PUBKEY:
                response = self.handle_get_ak_pubkey(request_data)
            elif command == Command.PERFORM_ATTESTATION:
                response = self.handle_perform_attestation(request_data)
            else:
                response = {"error": f"Unknown command: 0x{command:02x}"}
            
            # Send response
            if not self._send_response(sock, response):
                self.log(f"Failed to send response to {addr}")
            
        except Exception as e:
            self.log(f"Error handling client {addr}: {e}")
            try:
                self._send_response(sock, {"error": f"Internal error: {str(e)}"})
            except:
                pass
        
        finally:
            try:
                sock.close()
            except:
                pass
            self.log(f"Client disconnected: {addr}")

    def start(self):
        """Start the attestation agent server."""
        self.log(f"Starting Attestation Agent...")
        self.log(f"Listening on {self.host}:{self.port}")
        self.log(f"Quote script: {QUOTE_SCRIPT}")
        self.log(f"Output directory: {OUTDIR_BASE}")
        
        # Create output directory
        Path(OUTDIR_BASE).mkdir(parents=True, exist_ok=True)
        
        # Create server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(MAX_CLIENTS)
            self.log(f"Agent ready, waiting for connections...")
            
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                    
                    # Handle each client in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client_request,
                        args=(client_sock, client_addr),
                        daemon=True
                    )
                    client_thread.start()
                    
                except socket.error as e:
                    if self.running:
                        self.log(f"Socket error: {e}")
                        time.sleep(1)
                except KeyboardInterrupt:
                    self.running = False
                    break
                    
        except Exception as e:
            self.log(f"Server error: {e}")
        finally:
            self.shutdown()

    def shutdown(self):
        """Shutdown the agent server."""
        self.log("Shutting down...")
        self.running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.log("Agent stopped")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print(f"\n[AGENT] Received signal {signum}, shutting down...")
    global agent
    if agent:
        agent.shutdown()
    sys.exit(0)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SONiC Attestation Agent")
    parser.add_argument("--host", default=AGENT_HOST, help="Host to bind to")
    parser.add_argument("--port", type=int, default=AGENT_PORT, help="Port to bind to")
    parser.add_argument("--quote-script", default=QUOTE_SCRIPT, help="Quote generation script")
    parser.add_argument("--outdir", default=OUTDIR_BASE, help="Output directory for quotes")
    
    args = parser.parse_args()
    
    # Set up signal handlers
    global agent
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the agent
    agent = AttestationAgent(args.host, args.port)
    
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.shutdown()

if __name__ == "__main__":
    main()
