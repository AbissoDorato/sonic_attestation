#!/usr/bin/env python3
import argparse, base64, hashlib, json, os, shutil, subprocess, sys, tempfile, time, yaml, sqlite3, socket, struct
from pathlib import Path
from datetime import datetime

# --- Config defaults ---
VERIFY_QUOTE = os.environ.get("VERIFY_QUOTE", "./verify_attestation_VERIFIER.sh")  # your script
DEFAULT_PCRS = os.environ.get("PCRS", "13")
HALG = os.environ.get("HALG", "sha256")
BUFFER_SIZE = 8192
NONCE_LEN = 20
ATTESTATION_TIMEOUT = 30  # seconds

class Command:
    PERFORM_ATTESTATION = 0x01
    GET_AK_PUBKEY = 0x02

# --- Helpers ---
def sh(cmd, check=True, cwd=None, capture=False, env=None):
    if capture:
        return subprocess.run(
            cmd, check=check, cwd=cwd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        ).stdout
    subprocess.run(cmd, check=check, cwd=cwd, env=env)

def sha256_pem(pem_bytes: bytes) -> str:
    return hashlib.sha256(pem_bytes).hexdigest()

def load_yaml(path: Path):
    with open(path, "r") as f:
        content = f.read().strip()
    try:
        # Try YAML parse first
        return yaml.safe_load(content)
    except Exception:
        # Fallback: treat as plain text mapping
        data = {}
        for line in content.splitlines():
            if not line.strip():
                continue
            # Support "13 <number>" or "13: <number>"
            parts = line.replace(":", " ").split()
            if len(parts) >= 2:
                idx, val = parts[0], parts[1]
                # Convert big int to hex if it's purely digits
                if val.isdigit():
                    hexval = hex(int(val))[2:].rjust(64, "0")
                    data[int(idx)] = hexval.lower()
                else:
                    data[int(idx)] = val.lower()
        return {"sha256": data}


def save_bytes(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f: f.write(data)

def save_text(path: Path, s: str):
    save_bytes(path, s.encode())

def read_text(path: Path) -> str:
    with open(path, "r") as f: return f.read()

# --- Socket-based attestation transport ---
class SocketAttestationClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None

    def connect(self):
        """Establish socket connection to the attestation agent."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(ATTESTATION_TIMEOUT)
            self.sock.connect((self.host, self.port))
            print(f"[VERIFIER] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[VERIFIER] Failed to connect to {self.host}:{self.port}: {e}")
            return False

    def disconnect(self):
        """Close the socket connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send_command(self, command, payload):
        """Send a command with JSON payload."""
        try:
            json_payload = json.dumps(payload).encode('utf-8')
            message = struct.pack(f'<BI', command, len(json_payload)) + json_payload
            self.sock.sendall(message)
            return True
        except Exception as e:
            print(f"[VERIFIER] Failed to send command 0x{command:02x}: {e}")
            return False

    def _recv_all(self, n):
        """Helper function to receive 'n' bytes from socket."""
        data = bytearray()
        while len(data) < n:
            packet = self.sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def _recv_response(self):
        """Receive a response from the attestation agent."""
        try:
            # First, receive the length
            len_data = self._recv_all(4)
            if not len_data:
                print("[VERIFIER] No response length received")
                return None
            
            response_len = struct.unpack('<I', len_data)[0]
            
            # Then receive the actual response
            response_data = self._recv_all(response_len)
            if not response_data:
                print("[VERIFIER] No response data received")
                return None
            
            return json.loads(response_data.decode('utf-8'))
        except Exception as e:
            print(f"[VERIFIER] Failed to receive response: {e}")
            return None

    def get_ak_pubkey(self, node_id):
        """Request AK public key from the agent."""
        payload = {"node_id": node_id}
        
        if not self._send_command(Command.GET_AK_PUBKEY, payload):
            return None
        
        response = self._recv_response()
        if not response:
            return None
        
        return response

    def request_attestation(self, node_id, nonce_hex, pcrs=DEFAULT_PCRS):
        """Request attestation quote from the agent."""
        # node id could also be the tss 
        print(node_id)
        payload = {
            "node_id": node_id,
            "nonce_hex": nonce_hex,
            "pcrs": pcrs,
            "halg": HALG
        }
        
        print(f"[VERIFIER] Requesting attestation for node: {node_id}")
        print(f"[VERIFIER] Nonce: {nonce_hex}")
        print(f"[VERIFIER] PCRs: {pcrs}")
        
        if not self._send_command(Command.PERFORM_ATTESTATION, payload):
            return None
        
        response = self._recv_response()
        if not response:
            return None
        
        return response

def ask_quote_via_socket(node, host, port, nonce_hex, pcrs=DEFAULT_PCRS):
    """Get attestation quote via socket connection."""
    client = SocketAttestationClient(host, port)
    
    if not client.connect():
        return None
    
    try:
        # Request attestation
        response = client.request_attestation(node, nonce_hex, pcrs)
        if not response:
            print(f"[VERIFIER] Failed to get attestation response from {node}")
            return None
        
        # Create ./tmp under verifier directory
        base_tmp = Path(__file__).resolve().parent / "tmp"
        base_tmp.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=f"{node}_", dir=base_tmp))
        
        # Save quote artifacts
        if 'quote_msg_b64' in response:
            save_bytes(tmp / "quote.msg", base64.b64decode(response['quote_msg_b64']))
        if 'quote_sig_b64' in response:
            save_bytes(tmp / "quote.sig", base64.b64decode(response['quote_sig_b64']))
        if 'pcrs_yaml' in response:
            save_text(tmp / "pcrread.txt", response['pcrs_yaml'])
        if 'nonce_hex' in response:
            save_text(tmp / "nonce.hex", response['nonce_hex'])
        if 'ak_pub_b64' in response:
            save_bytes(tmp / "ak.pub", base64.b64decode(response['ak_pub_b64']))
        if 'quote_meta' in response:
            save_text(tmp / "quote_meta.json", json.dumps(response['quote_meta']))
        if 'pcrs_bin_b64' in response:
            save_bytes(tmp / "pcrs.bin", base64.b64decode(response['pcrs_bin_b64']))
        if 'ak_tss_sha256' in response:
            save_bytes(tmp / "ak.tss.sha256", response['ak_tss_sha256'].encode())
        
        print(f"[VERIFIER] Attestation artifacts saved to: {tmp}")
        return tmp
        
    finally:
        client.disconnect()

# --- Verify signature+nonce using your script ---
def verify_signature_with_script(verify_script, workdir: Path, ak_pub_env: Path | None = None) -> None:
    env = os.environ.copy()
    if ak_pub_env:
        env["AK_PUB"] = str(ak_pub_env)
    sh([verify_script, str(workdir)], check=True, env=env)
# --- PCR policy check ---
def parse_pcrs(pcrs_yaml_path: Path):
    data = load_yaml(pcrs_yaml_path)
    result = {}

    def normalize(v):
        if isinstance(v, int):
            # convert integer to 64-char hex digest
            return hex(v)[2:].rjust(64, "0").lower()
        elif isinstance(v, str):
            return v.strip().lower()
        else:
            raise ValueError(f"Unexpected PCR value type: {type(v)}")

    # Expected layout: {"bank":"sha256","pcrs":{"13":"a1..","14":"b2.."}}
    if "pcrs" in data:
        for k, v in data["pcrs"].items():
            result[int(k)] = normalize(v)
    else:
        # tpm2-tools style { "sha256": { "0": "....", ... } }
        bank = data.get("sha256") or {}
        for k, v in bank.items():
            result[int(k)] = normalize(v)

    return result

def check_pcr_allowlist(pcr_map, allowlist):
    failures = []
    for pcr_idx, digest in pcr_map.items():
        allowed = [d.lower() for d in allowlist.get(str(pcr_idx), [])]
        if allowed and digest not in allowed:
            failures.append(f"PCR{pcr_idx} digest {digest} not in allow-list")
    return failures

# --- Policy loading (YAML) ---
def load_policy_from_yaml(yaml_path: Path, node_id: str):
    ref = load_yaml(yaml_path)
    node = ref["nodes"][node_id]
    pol = ref["policies"][node["policy"]]
    allowlist = pol.get("pcrs", {}).get(HALG, {})
    measurements = pol.get("measurements", {})
    return node, allowlist, measurements

# --- CLI operations ---
def cmd_verify(args):
    # Load from YAML for simplicity (switch to SQLite later)
    node, allowlist, measurements = load_policy_from_yaml(Path(args.reference_yaml), args.node)
    
    # Parse endpoint (host:port)
    endpoint = node["endpoint"]
    if ":" in endpoint:
        host, port = endpoint.split(":", 1)
        port = int(port)
    else:
        host = endpoint
        port = 8087  # Default port
    
    #expexted ak tss
    expected_ak_tss_sha256 = node["ak_tss_sha256"].lower()

    # 1) fresh nonce
    nonce_hex = os.urandom(NONCE_LEN).hex()

    # 2) request fresh quote via socket
    tmp = ask_quote_via_socket(args.node, host, port, nonce_hex, pcrs=args.pcrs)
    if not tmp:
        print("FAIL: Could not get attestation quote")
        sys.exit(1)
    ak_pub_path = tmp / "ak.pub"

    try:
        # 3) verify signature+nonce
        #    also ensure AK pub matches enrollment
        ak_tss_path = tmp / "ak.tss.sha256"
        if ak_tss_path.exists():
            ak_tss_hex = ak_tss_path.read_text().strip().lower()   
            if ak_tss_hex != expected_ak_tss_sha256:
                print(f"FAIL: Mismatch in tss. {expected_ak_tss_sha256}, got {ak_tss_hex}")
                sys.exit(1)
            else :
                print(f"AK TSS SHA256 matches enrollment: {ak_tss_hex}")
        
        # Ensure nonce round-trip
        nonce_file = tmp / "nonce.hex"
        if nonce_file.exists():
            got_nonce = read_text(nonce_file).strip().lower()
            if got_nonce != nonce_hex:
                print(f"FAIL: Nonce mismatch: sent {nonce_hex}, attester returned {got_nonce}")
                sys.exit(1)

        # Call your verify_quote script
        ak_for_script = ak_pub_path if ak_pub_path.exists() else (Path(args.ak_pub_path) if getattr(args, "ak_pub_path", None) else None)
        verify_signature_with_script(VERIFY_QUOTE, tmp, ak_for_script)

        # 4) policy checks
        pcr_map = parse_pcrs(tmp / "pcrread.txt")
        failures = check_pcr_allowlist(pcr_map, allowlist)

        # Optional config checks (if you store extra files/digests in quote_meta.json)
        meta_path = tmp / "quote_meta.json"
        if meta_path.exists():
            meta = json.loads(read_text(meta_path))
            cfg_expected = measurements.get("CONFIG_DB_SHA256")
            if cfg_expected:
                cfg_seen = (meta.get("measurements") or {}).get("CONFIG_DB_SHA256")
                if not cfg_seen:
                    failures.append("CONFIG_DB_SHA256 missing in meta")
                elif cfg_seen.lower() != cfg_expected.lower():
                    failures.append(f"CONFIG_DB_SHA256 mismatch: expected {cfg_expected}, got {cfg_seen}")

        if failures:
            print("FAIL")
            for f in failures:
                print(" -", f)
            sys.exit(1)

        print("PASS")
        # Show quick summary
        used = ", ".join([f"{k}:{pcr_map[int(k)][:8]}" for k in sorted(map(int, allowlist.keys())) if int(k) in pcr_map])
        print(f"PCRs({HALG}) ok → {used}")
        
    finally:
        if not args.keep:
            shutil.rmtree(tmp, ignore_errors=True)

def cmd_enroll_socket(args):
    """
    Helper to print the AK hash via socket connection for YAML enrollment.
    """
    # Parse endpoint (host:port)
    endpoint = args.endpoint
    if ":" in endpoint:
        host, port = endpoint.split(":", 1)
        port = int(port)
    else:
        host = endpoint
        port = 8087  # Default port
    
    node = args.node
    client = SocketAttestationClient(host, port)
    
    if not client.connect():
        print("FAIL: Could not connect to attestation agent")
        sys.exit(1)
    
    try:
        response = client.get_ak_pubkey(node)
        if not response or 'ak_pub_b64' not in response:
            print("FAIL: Could not get AK public key")
            sys.exit(1)
        
        ak_pub = base64.b64decode(response['ak_pub_b64'])
        print(sha256_pem(ak_pub))
        
    finally:
        client.disconnect()

def cmd_continuous_verify(args):
    """
    Continuously verify attestation similar to DICE verifier.
    """
    # Load from YAML for simplicity
    node, allowlist, measurements = load_policy_from_yaml(Path(args.reference_yaml), args.node)
    
    # Parse endpoint (host:port)
    endpoint = node["endpoint"]
    if ":" in endpoint:
        host, port = endpoint.split(":", 1)
        port = int(port)
    else:
        host = endpoint
        port = 8087  # Default port
    
    expected_ak_sha256 = node["ak_pub_sha256"].lower()
    interval = args.interval
    
    print(f"[VERIFIER] Starting continuous verification for node: {args.node}")
    print(f"[VERIFIER] Target: {host}:{port}")
    print(f"[VERIFIER] Interval: {interval} seconds")
    print(f"[VERIFIER] Press Ctrl+C to stop")
    print("-" * 80)
    
    client = SocketAttestationClient(host, port)
    
    if not client.connect():
        print("FAIL: Could not connect to attestation agent")
        sys.exit(1)
    
    try:
        report_count = 0
        last_attestation = 0
        
        while True:
            current_time = time.time()
            
            if current_time - last_attestation >= interval:
                # Generate fresh nonce
                nonce_hex = os.urandom(NONCE_LEN).hex()
                
                # Request attestation
                response = client.request_attestation(args.node, nonce_hex, args.pcrs)
                if not response:
                    print("FAIL: Could not get attestation response")
                    continue
                
                report_count += 1
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
                print(f"\n[VERIFIER] [{timestamp}] Attestation Report #{report_count}")
                
                # Quick verification
                try:
                    # Verify nonce
                    got_nonce = response.get('nonce_hex', '').strip().lower()
                    if got_nonce != nonce_hex:
                        print(f"FAIL: Nonce mismatch: sent {nonce_hex}, got {got_nonce}")
                        continue
                    
                    # Verify AK if available
                    if 'ak_pub_b64' in response:
                        ak_pub = base64.b64decode(response['ak_pub_b64'])
                        ak_hex = sha256_pem(ak_pub)
                        if ak_hex != expected_ak_sha256:
                            print(f"FAIL: AK mismatch: expected {expected_ak_sha256}, got {ak_hex}")
                            continue
                    
                    # Parse and check PCRs if available
                    if 'pcrs_yaml' in response:
                        # Create temporary file for PCR parsing
                        tmp_pcr = Path(tempfile.mktemp(suffix='.yaml'))
                        save_text(tmp_pcr, response['pcrs_yaml'])
                        try:
                            pcr_map = parse_pcrs(tmp_pcr)
                            failures = check_pcr_allowlist(pcr_map, allowlist)
                            
                            if failures:
                                print("FAIL: PCR policy violations:")
                                for f in failures:
                                    print(f" - {f}")
                            else:
                                used = ", ".join([f"{k}:{pcr_map[int(k)][:8]}" for k in sorted(map(int, allowlist.keys())) if int(k) in pcr_map])
                                print(f"PASS: PCRs({HALG}) ok → {used}")
                                
                        finally:
                            tmp_pcr.unlink(missing_ok=True)
                    else:
                        print("PASS: Basic verification successful (no PCRs)")
                    
                except Exception as e:
                    print(f"ERROR: Verification failed: {e}")
                
                last_attestation = current_time
                print("-" * 80)
            
            time.sleep(1)  # Small sleep to prevent busy waiting
            
    except KeyboardInterrupt:
        print("\n[VERIFIER] Stopping continuous verification...")
    finally:
        client.disconnect()

def main():
    ap = argparse.ArgumentParser(description="SONiC Socket-based Verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify a node once")
    v.add_argument("--node", required=True)
    v.add_argument("--reference-yaml", required=True)
    v.add_argument("--pcrs", default=DEFAULT_PCRS)
    v.add_argument("--keep", action="store_true", help="keep temp artifacts")
    v.add_argument("--ak-pub-path", default=None, help="Path to AK public key PEM if verify script expects AK_PUB")

    v.set_defaults(func=cmd_verify)

    e = sub.add_parser("enroll-ak", help="Fetch AK hash via socket for YAML enrollment")
    e.add_argument("--node", required=True)
    e.add_argument("--endpoint", required=True, help="host:port of attestation agent")
    e.set_defaults(func=cmd_enroll_socket)
    
    c = sub.add_parser("continuous", help="Continuously verify attestation")
    c.add_argument("--node", required=True)
    c.add_argument("--reference-yaml", required=True)
    c.add_argument("--ak-pub-path", default=None, help="Path to AK public key PEM if verify script expects AK_PUB")
    c.add_argument("--pcrs", default=DEFAULT_PCRS)
    c.add_argument("--interval", type=int, default=15, help="Attestation interval in seconds")
    c.set_defaults(func=cmd_continuous_verify)

    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
