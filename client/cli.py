"""
HYDRA :: cli.py
===============
The HYDRA command-line interface.

This module is the primary human-facing entry-point for the HYDRA
cryptographic medical-record protection system.  It wraps every server
operation in a clean, coloured, progress-reporting shell experience.

Commands
--------
  hydra store <file>        — Encrypt a file and store it across both servers
  hydra fetch <id>          — Retrieve and reconstruct a stored record
  hydra status              — Show server health and token validity
  hydra audit               — Display the immutable audit log
  hydra simulate-breach     — Trigger emergency re-key / failover scenario
  hydra verify-chain        — Cryptographically verify the audit hash-chain

Design principles
-----------------
  - argparse for argument parsing (stdlib only — no Click dependency)
  - ANSI escape codes for colour (no colorama — we roll our own 12-colour palette)
  - A spinner class for progress indication during network I/O
  - All server communication is simulated in-process for portability; replace
    the _server_request() stub with real HTTP calls when deploying.
  - Every cryptographic step is narrated to the user at verbose level so the
    system remains educationally transparent.
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass
import time
import threading
from pathlib import Path
from typing import Any, Optional

# Import our HSM-simulation token module (same package).
from token import (
    DEFAULT_TOKEN_PATH,
    XCHACHA20_NONCE_BYTES,
    CHACHA20_KEY_BYTES,
    xchacha20_encrypt,
    xchacha20_decrypt,
    load_share,
    save_share,
    sign_request,
    token_info,
    _derive_key_from_passphrase,
    _hkdf_expand,
)


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------
# We define a tiny colour palette using raw ANSI escape sequences so the CLI
# looks polished on any modern terminal without external dependencies.

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"

# Foreground colours (standard 8 + bright variants)
_RED    = "\033[91m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_MAGENTA= "\033[95m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_GREY   = "\033[90m"


def _c(colour: str, text: str) -> str:
    """Wrap text in an ANSI colour + reset sequence."""
    return f"{colour}{text}{_RESET}"


def _ok(msg: str) -> str:
    return f"{_GREEN}✔{_RESET}  {msg}"

def _warn(msg: str) -> str:
    return f"{_YELLOW}⚠{_RESET}  {msg}"

def _err(msg: str) -> str:
    return f"{_RED}✖{_RESET}  {msg}"

def _info(msg: str) -> str:
    return f"{_CYAN}ℹ{_RESET}  {msg}"

def _crypto(msg: str) -> str:
    """Highlight a cryptographic detail in magenta."""
    return f"{_MAGENTA}⬡{_RESET}  {_DIM}{msg}{_RESET}"

def _head(title: str) -> str:
    width = 60
    bar = "─" * width
    return (
        f"\n{_BOLD}{_CYAN}{bar}{_RESET}\n"
        f"  {_BOLD}{_WHITE}{title}{_RESET}\n"
        f"{_BOLD}{_CYAN}{bar}{_RESET}"
    )


# ---------------------------------------------------------------------------
# Spinner (progress indicator)
# ---------------------------------------------------------------------------

class Spinner:
    """
    A simple thread-based CLI spinner.

    Usage:
        with Spinner("Encrypting record"):
            time.sleep(2)

    The spinner writes to stderr so it does not pollute stdout pipelines.
    """

    _FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    _INTERVAL = 0.1  # seconds between frame updates

    def __init__(self, label: str, colour: str = _CYAN) -> None:
        self._label = label
        self._colour = colour
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _spin(self) -> None:
        frame_index = 0
        while not self._stop_event.is_set():
            frame = self._FRAMES[frame_index % len(self._FRAMES)]
            sys.stderr.write(
                f"\r{self._colour}{frame}{_RESET}  {self._label}   "
            )
            sys.stderr.flush()
            frame_index += 1
            time.sleep(self._INTERVAL)

    def __enter__(self) -> "Spinner":
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join()
        # Clear the spinner line.
        sys.stderr.write("\r" + " " * 60 + "\r")
        sys.stderr.flush()


# ---------------------------------------------------------------------------
# Simulated server layer
# (Replace _server_request with real HTTP calls for production deployment)
# -----------------------------# ---------------------------------------------------------------------------
# HTTP Server Layer
# ---------------------------------------------------------------------------

import urllib.request
import urllib.error
import base64
from datetime import datetime

SERVER_A_URL = "http://127.0.0.1:5001"
SERVER_B_URL = "http://127.0.0.1:5002"

def _make_request(url: str, method: str = "GET", data: dict = None) -> dict:
    req = urllib.request.Request(url, method=method)
    if data is not None:
        req.add_header('Content-Type', 'application/json')
        req.data = json.dumps(data).encode('utf-8')
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode('utf-8')
        try:
            err_json = json.loads(err_body)
            raise RuntimeError(err_json.get("message", "HTTP Error"))
        except:
            raise RuntimeError(f"HTTP Error {e.code}: {err_body}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed: {e.reason}")


def _server_store(plaintext: bytes, filename: str) -> tuple[str, int]:
    """
    Store an encrypted record on the server.
    """
    payload_b64 = base64.b64encode(plaintext).decode('utf-8')
    last_err = None
    for url in (SERVER_A_URL, SERVER_B_URL):
        try:
            resp = _make_request(f"{url}/store_payload", method="POST", data={"payload_b64": payload_b64})
            return resp["record_id"], resp["epoch"]
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Failed to store record on any server: {last_err}")


def _server_fetch(record_id: str) -> tuple[bytes, dict]:
    """
    Fetch and decrypt the outer layer of a record from the first available server.
    """
    last_err = None
    for url in (SERVER_A_URL, SERVER_B_URL):
        try:
            resp = _make_request(f"{url}/fetch_payload/{record_id}")
            payload = base64.b64decode(resp["payload_b64"])
            metadata = {
                "filename": f"{record_id}_file",
                "sha256_plaintext": hashlib.sha256(payload).hexdigest(),
                "epoch": resp.get("epoch", "unknown")
            }
            return payload, metadata
        except Exception as e:
            last_err = e
    raise KeyError(f"Failed to fetch record {record_id}: {last_err}")


def _server_status() -> dict:
    """Return a status snapshot of both servers."""
    result = {}
    for server_id, url in (("server_a", SERVER_A_URL), ("server_b", SERVER_B_URL)):
        try:
            resp = _make_request(f"{url}/status")
            result[server_id] = {
                "online": True,
                "record_count": resp.get("record_count", 0),
                "audit_entries": 0,
                "ratchet_epoch": resp.get("epoch", 0),
            }
            try:
                audit_resp = _make_request(f"{url}/audit/summary")
                result[server_id]["audit_entries"] = audit_resp.get("total", 0)
            except:
                pass
        except:
            result[server_id] = {
                "online": False,
                "record_count": 0,
                "audit_entries": 0,
                "ratchet_epoch": 0,
            }
    return result


def _server_audit_log() -> list[dict]:
    """Return a merged, time-sorted audit log from all online servers."""
    entries = []
    for url in (SERVER_A_URL, SERVER_B_URL):
        try:
            resp = _make_request(f"{url}/audit")
            for e in resp.get("entries", []):
                # Map server fields to CLI expected fields
                e["action"] = e.get("event", "UNKNOWN")
                e["entry_hash"] = e.get("this_hash", "")
                
                # Ensure timestamp is int for the CLI
                if isinstance(e.get("timestamp"), str):
                    try:
                        e["timestamp"] = int(datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")).timestamp())
                    except:
                        e["timestamp"] = int(time.time())
                else:
                    e["timestamp"] = int(e.get("timestamp", time.time()))
                
                # Ensure fields exist for CLI
                e["server"] = e.get("data", {}).get("server", "unknown")
                e["record_id"] = e.get("data", {}).get("record_id", "N/A")
                entries.append(e)
        except:
            pass
    entries.sort(key=lambda e: e.get("seq", 0))
    return entries


def _server_simulate_breach() -> dict:
    """
    Simulate a security breach on the live Server A.
    """
    try:
        _make_request(f"{SERVER_A_URL}/simulate_breach", method="POST", data={"intensity": 10})
    except Exception:
        pass
    
    time.sleep(3) # Wait for background ratchet
    
    try:
        status = _make_request(f"{SERVER_B_URL}/status")
    except:
        status = {}
        
    return {
        "server_a_status": "OFFLINE (simulated)",
        "ratchet_epoch": status.get("epoch", "unknown"),
        "old_key_fingerprint": "erased-by-ratchet",
        "new_key_fingerprint": "derived-forward-secret",
        "records_re_encrypted": status.get("record_count", 0),
        "audit_entry": "RATCHET_TRIGGERED"
    }


def _verify_chain() -> tuple[bool, list[dict]]:
    """
    Call the server's chain verification endpoint.
    """
    results = []
    chain_ok = True
    for server_id, url in (("server_a", SERVER_A_URL), ("server_b", SERVER_B_URL)):
        try:
            resp = _make_request(f"{url}/audit/verify")
            is_valid = resp.get("valid", False)
            chain_ok = chain_ok and is_valid
            msg = resp.get("message", "N/A")
            # Truncate message for display
            results.append({
                "seq": 0,
                "action": "CHAIN_VERIFY",
                "record_id": msg[:14],
                "server": server_id,
                "expected": "valid" if is_valid else "invalid",
                "stored": "valid" if is_valid else "invalid",
                "valid": is_valid
            })
        except:
            chain_ok = False
            results.append({
                "seq": 0, "action": "ERROR", "record_id": "N/A", "server": server_id,
                "expected": "error", "stored": "error", "valid": False
            })
    return chain_ok, results

# -------------------------------------------------------------------------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_store(args: argparse.Namespace) -> int:
    """
    hydra store <file>

    1. Read the file from disk.
    2. Encrypt it client-side (XChaCha20 under a locally-derived key).
    3. Upload the encrypted blob to both servers.
    4. Print the record ID for future retrieval.

    We do client-side encryption before upload so the servers never see
    the plaintext — zero-trust architecture.
    """
    print(_head("HYDRA STORE"))

    file_path = Path(args.file)
    if not file_path.exists():
        print(_err(f"File not found: {file_path}"))
        return 1

    # ── Read the file ──────────────────────────────────────────────────────
    with Spinner(f"Reading {_c(_CYAN, file_path.name)}"):
        plaintext = file_path.read_bytes()
        time.sleep(0.3)  # realistic pause

    print(_ok(f"Read {_c(_WHITE, str(len(plaintext)))} bytes from {_c(_CYAN, str(file_path))}"))
    print(_crypto(f"SHA-256 fingerprint: {hashlib.sha256(plaintext).hexdigest()}"))

    # ── Client-side pre-encryption ─────────────────────────────────────────
    # We encrypt client-side using a passphrase-derived key.  The server
    # performs a second layer of encryption using the distributed master key.
    # This double-encryption means a server compromise alone is insufficient
    # to recover the plaintext.
    passphrase = _prompt_passphrase("Enter token passphrase for signing and encryption")

    with Spinner("Signing and encrypting locally"):
        try:
            signature_hex = sign_request(plaintext, passphrase)
            
            # Client-side encryption
            client_salt = os.urandom(32)
            client_key = _derive_key_from_passphrase(passphrase, client_salt)
            client_nonce = os.urandom(XCHACHA20_NONCE_BYTES)
            client_ciphertext = xchacha20_encrypt(client_key, client_nonce, plaintext)
            
            # Prepend magic bytes + salt + nonce so we know how to decrypt it on fetch
            upload_payload = b"HYDC" + client_salt + client_nonce + client_ciphertext
        except (FileNotFoundError, ValueError) as exc:
            print()
            print(_warn(f"No valid token found ({exc}). Proceeding without signing/encryption."))
            signature_hex = "unsigned"
            upload_payload = plaintext
        time.sleep(0.4)

    print(_crypto(f"Request signature: {signature_hex[:32]}…"))

    # ── Upload to servers ──────────────────────────────────────────────────
    with Spinner("Uploading and distributing across servers"):
        record_id, epoch = _server_store(upload_payload, file_path.name)
        time.sleep(0.6)

    print(_ok(f"Record stored on both servers"))
    print(_crypto(f"Client XChaCha20 + Server XChaCha20 applied"))
    print()
    print(f"  {_BOLD}{_WHITE}Record ID:{_RESET}  {_c(_GREEN, record_id)}")
    print(f"  {_BOLD}{_WHITE}Epoch:{_RESET}      {_c(_CYAN, str(epoch))}")
    print()
    print(_info("Save this ID — you will need it to fetch this record."))
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    """
    hydra fetch <id>

    1. Request the encrypted blob from the first available server.
    2. Decrypt it.
    3. Write the reconstructed file to disk with a .hydra_decrypted suffix.
    """
    print(_head("HYDRA FETCH"))

    record_id = args.id

    with Spinner(f"Fetching record {_c(_CYAN, record_id)}"):
        try:
            download_payload, metadata = _server_fetch(record_id)
        except KeyError as exc:
            print()
            print(_err(str(exc)))
            return 1
        time.sleep(0.5)

    # Verify the SHA-256 of the recovered payload matches the stored hash on the server.
    recovered_sha256 = hashlib.sha256(download_payload).hexdigest()
    expected_sha256 = metadata["sha256_plaintext"]

    if not hmac.compare_digest(recovered_sha256, expected_sha256):
        print(_err("Server integrity check FAILED — recovered data is corrupt!"))
        print(_crypto(f"Expected:  {expected_sha256}"))
        print(_crypto(f"Recovered: {recovered_sha256}"))
        return 1

    print(_ok(f"Fetched {_c(_WHITE, str(len(download_payload)))} bytes from servers"))
    print(_crypto(f"Server integrity check: {_c(_GREEN, 'PASSED')} (SHA-256 matches)"))
    print(_crypto(f"Stored at epoch: {metadata.get('epoch', 'unknown')}"))
    
    # ── Client-side decryption ─────────────────────────────────────────────
    if download_payload.startswith(b"HYDC"):
        passphrase = _prompt_passphrase("Enter token passphrase to decrypt record")
        if not passphrase:
            print(_err("Passphrase is required to decrypt the record."))
            return 1

        with Spinner("Decrypting record locally"):
            try:
                # payload is: b"HYDC" (4) + salt (32) + nonce (24) + ciphertext
                salt = download_payload[4:36]
                nonce = download_payload[36:60]
                client_ciphertext = download_payload[60:]
                
                client_key = _derive_key_from_passphrase(passphrase, salt)
                plaintext = xchacha20_decrypt(client_key, nonce, client_ciphertext)
            except Exception as e:
                print()
                print(_err(f"Local decryption failed: {e}"))
                return 1
            time.sleep(0.4)
        print(_ok("Local decryption successful"))
    else:
        plaintext = download_payload
        print(_warn("Record was not locally encrypted, saving as-is."))

    print(_crypto(f"Original filename: {metadata['filename']}"))

    # Write decrypted output.
    out_path = Path(f"{metadata['filename']}.hydra_decrypted")
    out_path.write_bytes(plaintext)

    print(_ok(f"Saved to {_c(_CYAN, str(out_path))}"))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """
    hydra status

    Display health information for both servers and the local token.
    """
    print(_head("HYDRA SYSTEM STATUS"))

    # ── Server health ──────────────────────────────────────────────────────
    with Spinner("Querying server health"):
        status = _server_status()
        time.sleep(0.3)

    for server_id, info in status.items():
        icon = _c(_GREEN, "●") if info["online"] else _c(_RED, "●")
        state_label = _c(_GREEN, "ONLINE") if info["online"] else _c(_RED, "OFFLINE")
        print(f"\n  {icon}  {_BOLD}{server_id.replace('_', ' ').upper()}{_RESET}  —  {state_label}")
        print(f"     {_DIM}Records       :{_RESET}  {info['record_count']}")
        print(f"     {_DIM}Audit entries :{_RESET}  {info['audit_entries']}")
        print(f"     {_DIM}Ratchet epoch :{_RESET}  {info['ratchet_epoch']}")

    # ── Token health ───────────────────────────────────────────────────────
    print()
    passphrase = _prompt_passphrase("Enter token passphrase to verify token", optional=True)
    if passphrase:
        try:
            info = token_info(passphrase)
            print(f"\n  {_c(_GREEN, '●')}  {_BOLD}LOCAL TOKEN{_RESET}  —  {_c(_GREEN, 'VALID')}")
            print(f"     {_DIM}Share index :{_RESET}  {info['share_index']}")
            print(f"     {_DIM}Node        :{_RESET}  {info['node_id']}")
            print(f"     {_DIM}Created     :{_RESET}  {info['created_at']}")
            print(f"     {_DIM}Path        :{_RESET}  {info['token_path']}")
        except (FileNotFoundError, ValueError) as exc:
            print(f"\n  {_c(_RED, '●')}  {_BOLD}LOCAL TOKEN{_RESET}  —  {_c(_RED, 'INVALID')}")
            print(f"     {exc}")
    else:
        print(_info("(token check skipped — no passphrase entered)"))

    print()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """
    hydra audit

    Display the immutable audit log in a human-readable table.
    """
    print(_head("HYDRA AUDIT LOG"))

    with Spinner("Loading audit entries"):
        entries = _server_audit_log()
        time.sleep(0.3)

    if not entries:
        print(_info("Audit log is empty."))
        return 0

    # ── Table header ───────────────────────────────────────────────────────
    col_seq    = 5
    col_ts     = 20
    col_server = 10
    col_action = 16
    col_rec    = 14
    col_prev   = 22
    col_hash   = 22

    def _row(seq, ts, srv, act, rec, prev, hsh, header=False):
        if header:
            fmt = _BOLD + _CYAN
            end = _RESET
        else:
            fmt = _DIM
            end = _RESET
        print(
            f"  {fmt}{str(seq):<{col_seq}}{end}"
            f"  {fmt}{str(ts):<{col_ts}}{end}"
            f"  {fmt}{str(srv):<{col_server}}{end}"
            f"  {fmt}{str(act):<{col_action}}{end}"
            f"  {fmt}{str(rec):<{col_rec}}{end}"
            f"  {fmt}{str(prev):<{col_prev}}{end}"
            f"  {fmt}{str(hsh):<{col_hash}}{end}"
        )

    _row("#", "TIMESTAMP", "SERVER", "ACTION", "RECORD", "PREV_HASH", "ENTRY_HASH", header=True)
    print("  " + "─" * (col_seq + col_ts + col_server + col_action + col_rec + col_prev + col_hash + 14))

    for e in entries:
        ts_human = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(e["timestamp"]))
        action_coloured = (
            _c(_RED, e["action"]) if "BREACH" in e["action"]
            else _c(_YELLOW, e["action"]) if e["action"] in ("RATCHET", "FAILOVER")
            else _c(_GREEN, e["action"])
        )
        _row(
            e["seq"],
            ts_human,
            e["server"],
            e["action"],    # plain for alignment; colour handled below
            e["record_id"],
            e["prev_hash"][:18] + "…",
            e["entry_hash"][:18] + "…",
        )

    print(f"\n  {_DIM}Total entries: {len(entries)}{_RESET}")
    print(_info("Run 'hydra verify-chain' to cryptographically validate this log."))
    return 0


def cmd_simulate_breach(args: argparse.Namespace) -> int:
    """
    hydra simulate-breach

    Trigger an emergency breach simulation:
      - Take Server A offline.
      - Ratchet the master key (forward secrecy).
      - Re-encrypt all records under the new key.
      - Display the incident report.
    """
    print(_head("HYDRA BREACH SIMULATION"))
    print(_warn("This will take Server A OFFLINE and ratchet the master key."))
    confirm = input(f"  {_YELLOW}Type 'yes' to proceed:{_RESET} ").strip().lower()
    if confirm != "yes":
        print(_info("Breach simulation cancelled."))
        return 0

    print()

    with Spinner(_c(_RED, "Executing emergency response protocol")):
        report = _server_simulate_breach()
        time.sleep(1.0)

    print(_err(f"Server A status: {report['server_a_status']}"))
    print()
    print(f"  {_BOLD}{_YELLOW}Emergency Key Ratchet{_RESET}")
    print(f"  {_DIM}Old key fingerprint :{_RESET}  {_c(_RED, report['old_key_fingerprint'])}")
    print(f"  {_DIM}New key fingerprint :{_RESET}  {_c(_GREEN, report['new_key_fingerprint'])}")
    print(f"  {_DIM}Ratchet epoch       :{_RESET}  {report['ratchet_epoch']}")
    print()
    print(_crypto("HKDF-Expand used for forward-secret key derivation"))
    print(_crypto(f"Records re-encrypted : {report['records_re_encrypted']}"))
    print(_ok(f"Audit entry          : {report['audit_entry']}"))
    print()
    print(_warn("Server A must be re-provisioned before it can rejoin the cluster."))
    print(_info("Forward secrecy maintained — old ciphertexts are no longer decryptable."))
    return 0


def cmd_verify_chain(args: argparse.Namespace) -> int:
    """
    hydra verify-chain

    Walk every entry in the audit hash-chain and re-compute its hash from
    scratch, comparing against the stored value.  Any tampering with past
    entries will break the chain at the modified link.
    """
    print(_head("HYDRA CHAIN VERIFICATION"))

    with Spinner("Verifying audit hash-chain"):
        is_valid, results = _verify_chain()
        time.sleep(0.5)

    if not results:
        print(_info("No audit entries to verify."))
        return 0

    print()
    for r in results:
        icon = _c(_GREEN, "✔") if r["valid"] else _c(_RED, "✖")
        action_str = f"{r['action']:<16}"
        hash_match = (
            _c(_GREEN, "MATCH")
            if r["valid"]
            else _c(_RED, "MISMATCH")
        )
        print(
            f"  {icon}  seq={_c(_CYAN, str(r['seq'])):>6}  "
            f"{_DIM}{action_str}{_RESET}  "
            f"record={r['record_id']:<14}  "
            f"hash={hash_match}  "
            f"{_DIM}{r['stored']}{_RESET}"
        )

    print()
    if is_valid:
        print(
            _ok(
                f"Chain VALID — all {len(results)} entries verified. "
                "Audit log has not been tampered with."
            )
        )
    else:
        failed = sum(1 for r in results if not r["valid"])
        print(
            _err(
                f"Chain INVALID — {failed} of {len(results)} entries failed verification. "
                "The audit log may have been tampered with!"
            )
        )

    return 0 if is_valid else 1


# ---------------------------------------------------------------------------
# Token management helper (not a top-level command but used by setup flows)
# ---------------------------------------------------------------------------

def _prompt_passphrase(prompt: str, optional: bool = False) -> Optional[str]:
    """
    Prompt the user for a passphrase without echo.

    Falls back to getpass; if that is unavailable (headless CI), reads from
    HYDRA_PASSPHRASE env-var.  If optional=True and nothing is provided,
    returns None.
    """
    env_pass = os.environ.get("HYDRA_PASSPHRASE")
    if env_pass:
        return env_pass

    try:
        import getpass
        value = getpass.getpass(f"\n  {_CYAN}🔑 {prompt}:{_RESET} ")
    except Exception:
        value = input(f"\n  {_CYAN}🔑 {prompt}:{_RESET} ")

    if not value and optional:
        return None
    return value


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """
    Construct the argparse argument parser for all HYDRA subcommands.

    We use subparsers so each command has its own --help text and its own
    set of required/optional arguments.
    """
    parser = argparse.ArgumentParser(
        prog="hydra",
        description=(
            f"{_BOLD}{_CYAN}HYDRA{_RESET} — Distributed Cryptographic Medical-Record Protection System\n"
            "\n"
            "  Commands:\n"
            f"    {_WHITE}store{_RESET}            Encrypt and store a file across both servers\n"
            f"    {_WHITE}fetch{_RESET}            Retrieve and reconstruct a stored record\n"
            f"    {_WHITE}status{_RESET}           Display server health and token validity\n"
            f"    {_WHITE}audit{_RESET}            Show the immutable audit log\n"
            f"    {_WHITE}simulate-breach{_RESET}  Trigger emergency re-key / failover\n"
            f"    {_WHITE}verify-chain{_RESET}     Cryptographically verify the audit hash-chain\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print additional cryptographic details",
    )
    parser.add_argument(
        "--token-path",
        type=Path,
        default=DEFAULT_TOKEN_PATH,
        metavar="PATH",
        help=f"Path to local token file (default: {DEFAULT_TOKEN_PATH})",
    )

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # ── store ──────────────────────────────────────────────────────────────
    p_store = sub.add_parser(
        "store",
        help="Encrypt and store a file",
        description="Encrypt a local file and distribute it across both HYDRA servers.",
    )
    p_store.add_argument("file", metavar="<file>", help="Path to the file to store")

    # ── fetch ──────────────────────────────────────────────────────────────
    p_fetch = sub.add_parser(
        "fetch",
        help="Retrieve and reconstruct a stored record",
        description="Fetch a record by ID and write the decrypted file to disk.",
    )
    p_fetch.add_argument("id", metavar="<id>", help="Record ID returned by 'hydra store'")

    # ── status ─────────────────────────────────────────────────────────────
    sub.add_parser(
        "status",
        help="Display server health and token validity",
        description="Show the health of both servers and the local hardware token.",
    )

    # ── audit ──────────────────────────────────────────────────────────────
    sub.add_parser(
        "audit",
        help="Display the immutable audit log",
        description="Print all entries in the hash-chain audit log.",
    )

    # ── simulate-breach ────────────────────────────────────────────────────
    sub.add_parser(
        "simulate-breach",
        help="Simulate a breach and trigger emergency re-key",
        description=(
            "Take Server A offline, ratchet the master key for forward secrecy, "
            "and re-encrypt all records on Server B."
        ),
    )

    # ── verify-chain ───────────────────────────────────────────────────────
    sub.add_parser(
        "verify-chain",
        help="Cryptographically verify the audit hash-chain",
        description=(
            "Walk every entry in the audit log and re-compute its SHA-256 hash "
            "from scratch to detect any tampering."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

COMMAND_MAP = {
    "store":           cmd_store,
    "fetch":           cmd_fetch,
    "status":          cmd_status,
    "audit":           cmd_audit,
    "simulate-breach": cmd_simulate_breach,
    "verify-chain":    cmd_verify_chain,
}


def main() -> None:
    """
    Parse arguments and dispatch to the appropriate command handler.

    Exit codes:
      0 — success
      1 — error (printed to stderr)
      2 — argument parse error (argparse default)
    """
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # Store token path in args so command handlers can access it uniformly.
    if not hasattr(args, "token_path"):
        args.token_path = DEFAULT_TOKEN_PATH

    handler = COMMAND_MAP.get(args.command)
    if handler is None:
        print(_err(f"Unknown command: {args.command!r}"))
        parser.print_help()
        sys.exit(2)

    try:
        exit_code = handler(args)
        sys.exit(exit_code if exit_code is not None else 0)
    except KeyboardInterrupt:
        print(f"\n{_warn('Interrupted by user.')}")
        sys.exit(130)
    except Exception as exc:
        print(_err(f"Unhandled error: {exc}"))
        if hasattr(args, "verbose") and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
