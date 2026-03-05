# logger.py
import os
import time
import threading
import traceback
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =========================
# LOG DIRECTORY SETUP
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "..", "logs")

os.makedirs(LOGS_DIR, exist_ok=True)

SESSION_LOG = os.path.join(LOGS_DIR, "session.log")
SECURITY_LOG = os.path.join(LOGS_DIR, "security.log")
ERROR_LOG = os.path.join(LOGS_DIR, "error.log")

# Thread lock to prevent race conditions
log_lock = threading.Lock()

# Persistent state for sequence numbering
_sequence_number = 0

# Load Log Encryption Key
LOG_KEY_PATH = os.path.join(BASE_DIR, "keys", "log_key.bin")
try:
    with open(LOG_KEY_PATH, "rb") as f:
        LOG_KEY = f.read()
    aesgcm = AESGCM(LOG_KEY)
except FileNotFoundError:
    LOG_KEY = None
    print(f"[LOGGER] WARNING: Log encryption key not found at {LOG_KEY_PATH}. Logging in plaintext.")

# =========================
# INTERNAL WRITE FUNCTION
# =========================
def _write_log(filepath, message):
    global _sequence_number
    with log_lock:
        _sequence_number += 1
        
        if LOG_KEY:
            # Encrypt with AES-GCM
            nonce = os.urandom(12)
            # Add sequence number to plaintext for audit integrity
            payload = f"SEQ={_sequence_number} | {message}".encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, payload, None)
            
            # Write as Base64 JSON envelope
            entry = {
                "seq": _sequence_number,
                "nonce": base64.b64encode(nonce).decode("utf-8"),
                "data": base64.b64encode(ciphertext).decode("utf-8")
            }
            line = json.dumps(entry)
        else:
            line = f"SEQ={_sequence_number} | {message}"

        with open(filepath, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()


# =========================
# GENERAL EVENT LOG
# =========================
def log_event(username, action, status, reason=""):
    """
    Logs normal system activity:
    login, logout, access, trust changes, OTP, VPN decisions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} | USER={username} | ACTION={action} | STATUS={status} | REASON={reason}"
    _write_log(SESSION_LOG, msg)


# =========================
# SUSPICIOUS / SECURITY LOG
# =========================
def log_suspicious(username, reason, metadata=""):
    """
    Logs suspicious behavior:
    brute-force, RBAC violation, rate-limit, unusual behavior
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = f"{timestamp} | USER={username} | ⚠ SUSPICIOUS | {reason} | {metadata}"
    _write_log(SECURITY_LOG, msg)


# =========================
# TRUST SCORE LOG
# =========================
def log_trust_change(username, old_score, new_score, reason):
    """
    Explicit trust score transitions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"{timestamp} | USER={username} | TRUST_CHANGE | "
        f"{old_score} → {new_score} | REASON={reason}"
    )
    _write_log(SESSION_LOG, msg)


# =========================
# VPN / ZERO TRUST LOG
# =========================
def log_vpn_decision(username, role, path, decision, trust_score):
    """
    Logs Zero Trust VPN policy decisions
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    msg = (
        f"{timestamp} | USER={username} | ROLE={role} | PATH={path} | "
        f"DECISION={decision} | TRUST={trust_score}"
    )
    _write_log(SESSION_LOG, msg)


# =========================
# ERROR LOGGING
# =========================
def log_error(context, exc: Exception):
    """
    Logs uncaught exceptions with stack trace
    """
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    trace = traceback.format_exc()
    msg = (
        f"{timestamp} | ❌ ERROR | CONTEXT={context}\n"
        f"{trace}\n"
        f"{'-'*60}"
    )
    _write_log(ERROR_LOG, msg)
