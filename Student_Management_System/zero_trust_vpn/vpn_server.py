# zero_trust_vpn/vpn_server.py
# =========================
# Zero Trust Policy Server with RSA + AES Encryption
# =========================

import socket
import json
import jwt
import threading
import os
import sys
import struct
from dotenv import load_dotenv

# Add the zero_trust_vpn directory to sys.path
sys.path.insert(0, os.path.dirname(__file__))
import time
import secrets
from crypto_utils import decrypt_payload, load_private_key

load_dotenv()

HOST = "127.0.0.1"
PORT = 5012
JWT_SECRET = os.getenv("JWT_SECRET", "your_jwt_secret_key")

PRIVATE_KEY_PATH = os.path.join(os.path.dirname(__file__), "keys", "private.pem")

# Load RSA private key on startup
try:
    PRIVATE_KEY = load_private_key(PRIVATE_KEY_PATH)
    print(f"[VPN] RSA private key loaded from {PRIVATE_KEY_PATH}")
except FileNotFoundError:
    print(f"[VPN] ERROR: RSA private key not found at {PRIVATE_KEY_PATH}")
    print("[VPN] Run: python zero_trust_vpn/generate_keys.py")
    sys.exit(1)

try:
    from logger import log_event, log_suspicious, log_vpn_decision, log_error
except ImportError:
    def log_event(m): print(f"[LOG] {m}")
    def log_suspicious(u, m, d): print(f"[SUSPICIOUS] {u}: {m} | {d}")
    def log_vpn_decision(u, r, p, a, t): print(f"[VPN] {a} | {u} | {r} | {p} | trust:{t}")
    def log_error(m): print(f"[ERROR] {m}")

# In-memory trust store
trust_scores = {}

# Paths that are always allowed regardless of role
PUBLIC_PATHS = [
    "/logout",
    "/login",
    "/public-request-help",
    "/verify_otp",
    "/dashboard",  # Handled via RBAC but allowing public check fallback
    "/restricted",  # Low-trust landing page — must be reachable without RBAC penalty to avoid redirect loop
]

# RBAC policy
POLICY = {
    "student": ["/student", "/dashboard"],
    "parent":  ["/parent",  "/dashboard"],
    "faculty": ["/faculty", "/dashboard"],
    "admin":   ["/admin",   "/faculty",  "/dashboard"],  # admin can access faculty routes too
}

BASE_TRUST = 100

# How many points to deduct per RBAC violation
RBAC_PENALTY = 5  # was 15 — too aggressive

# Trust threshold below which session is terminated
TERMINATE_THRESHOLD = 10  # was 40 — way too aggressive

# Replay protection threshold (seconds)
REPLAY_WINDOW = 30
seen_nonces = set()
nonce_lock  = threading.Lock()

def allowed(role, path):
    for allowed_path in POLICY.get(role, []):
        if path.startswith(allowed_path):
            return True
    return False


def handle_client(conn, addr):
    print(f"[VPN TRACE] Handling client from {addr}")
    try:
        # Read 4-byte total message length
        header = conn.recv(4)
        if not header or len(header) < 4:
            print(f"[VPN TRACE] No header from {addr}")
            return
        total_len = struct.unpack(">I", header)[0]
        print(f"[VPN TRACE] total_len: {total_len}")

        # Read the entire message body
        wire_data = b""
        while len(wire_data) < total_len:
            part = conn.recv(min(4096, total_len - len(wire_data)))
            if not part: break
            wire_data += part
        
        print(f"[VPN TRACE] wire_data len: {len(wire_data)}")
        
        if len(wire_data) < total_len:
            print(f"[VPN TRACE] Incomplete message from {addr}")
            return

        # ─── RSA + AES Decrypt ───────────────────────────────────────────────
        try:
            plaintext = decrypt_payload(wire_data, PRIVATE_KEY)
            print(f"[VPN TRACE] Decryption successful.")
            request_data = json.loads(plaintext)
            print(f"[VPN TRACE] JSON parsed: {request_data.get('action', 'PATH_CHECK')}")
        except Exception as e:
            err_msg = f"DECRYPT_ERROR: {str(e)}"
            print(f"[VPN TRACE] {err_msg}")
            conn.sendall(err_msg.encode())
            return

        # ─── Replay Protection ───────────────────────────────────────────────
        ts = request_data.get("ts", 0)
        nonce = request_data.get("nonce")
        
        if abs(time.time() - ts) > REPLAY_WINDOW:
            print(f"[VPN] REPLAY_ATTACK_DETECTED: Timestamp {ts} is outside window.")
            conn.sendall(b"REPLAY_DETECTED")
            return
            
        with nonce_lock:
            if nonce in seen_nonces:
                print(f"[VPN] REPLAY_ATTACK_DETECTED: Nonce {nonce} already seen.")
                conn.sendall(b"REPLAY_DETECTED")
                return
            seen_nonces.add(nonce)

        path = request_data.get("path", "")
        action = request_data.get("action", "PATH_CHECK")

        # ─── Auth Resolution (JWT) ────────────────────────────────
        jwt_token = request_data.get("jwt")
        print(f"[VPN DEBUG] JWT: {jwt_token}")
        if not jwt_token:
            conn.sendall(b"AUTH_REQUIRED")
            return
        try:
            payload = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
            username = payload["sub"]
            role = payload["role"]
        except Exception as e:
            print(f"[VPN] JWT decode failed: {e}")
            conn.sendall(b"TOKEN_INVALID")
            return

        # ─── Default: Path Check (RBAC) ──────────────────────────────────────
        trust_scores.setdefault(username, BASE_TRUST)
        trust = trust_scores[username]

        # ─── Always allow public/utility paths ──────────────────────────────
        if any(path.startswith(p) for p in PUBLIC_PATHS):
            log_vpn_decision(username, role, path, "ALLOW_PUBLIC", trust)
            conn.sendall(f"ALLOWED:{path}".encode())
            return

        # ─── Low trust → terminate session ──────────────────────────────────
        if trust < TERMINATE_THRESHOLD:
            log_suspicious(username, "Trust critically low", f"Trust={trust}")
            conn.sendall(b"SESSION_TERMINATED_LOW_TRUST")
            return

        # ─── RBAC check ─────────────────────────────────────────────────────
        if not allowed(role, path):
            trust_scores[username] = max(0, trust_scores[username] - RBAC_PENALTY)
            trust = trust_scores[username]

            response = json.dumps({
                "action": "JWT_DOWNGRADED",
                "trust":  trust,
                "reason": "RBAC_VIOLATION",
            })

            log_suspicious(username, f"RBAC violation accessing {path}", f"Trust reduced to {trust}")
            log_vpn_decision(username, role, path, "DENY_RBAC", trust)
            conn.sendall(response.encode())
            return

        # ─── Allowed ────────────────────────────────────────────────────────
        log_vpn_decision(username, role, path, "ALLOW", trust)
        conn.sendall(f"ALLOWED:{path}".encode())

    except Exception as e:
        print(f"[VPN] Handler error: {e}")
    finally:
        conn.close()


def session_cleanup_task():
    """Background thread to prune dead VPN sessions."""
    while True:
        time.sleep(60)
        with session_lock:
            now = time.time()
            to_delete = [sid for sid, data in active_sessions.items() 
                         if now - data["last_seen"] > SESSION_TIMEOUT]
            for sid in to_delete:
                print(f"[VPN] SESSION_TIMEOUT: Expiring session {sid}")
                del active_sessions[sid]

threading.Thread(target=session_cleanup_task, daemon=True).start()

print(f"[VPN] Zero Trust Policy Server (RSA+AES encrypted) running on {HOST}:{PORT}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(50)

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()