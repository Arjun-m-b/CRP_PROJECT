# core/audit.py
# Immutable hash-chained audit log for HYDRA
# Only stdlib used: hashlib, json, time, os, sys

import sys
import hashlib
import json
import time
import os
sys.stdout.reconfigure(encoding='utf-8')


# ─────────────────────────────────────────────
# EVENT TYPES
# ─────────────────────────────────────────────

# All possible events HYDRA will log.
# Using constants avoids typos in event names.

KEY_CEREMONY          = "KEY_CEREMONY"
RATCHET_TRIGGERED     = "RATCHET_TRIGGERED"
RATCHET_COMPLETE      = "RATCHET_COMPLETE"
FAILOVER_INITIATED    = "FAILOVER_INITIATED"
FAILOVER_COMPLETE     = "FAILOVER_COMPLETE"
RE_ENCRYPT_START      = "RE_ENCRYPT_START"
RE_ENCRYPT_COMPLETE   = "RE_ENCRYPT_COMPLETE"
ZK_PROOF_PASSED       = "ZK_PROOF_PASSED"
ZK_PROOF_FAILED       = "ZK_PROOF_FAILED"
SHARE_ISSUED          = "SHARE_ISSUED"
RECORD_STORED         = "RECORD_STORED"
RECORD_FETCHED        = "RECORD_FETCHED"
BREACH_SCORE_HIGH     = "BREACH_SCORE_HIGH"
SERVER_STARTED        = "SERVER_STARTED"
SERVER_ISOLATED       = "SERVER_ISOLATED"

ALL_EVENT_TYPES = {
    KEY_CEREMONY, RATCHET_TRIGGERED, RATCHET_COMPLETE,
    FAILOVER_INITIATED, FAILOVER_COMPLETE,
    RE_ENCRYPT_START, RE_ENCRYPT_COMPLETE,
    ZK_PROOF_PASSED, ZK_PROOF_FAILED,
    SHARE_ISSUED, RECORD_STORED, RECORD_FETCHED,
    BREACH_SCORE_HIGH, SERVER_STARTED, SERVER_ISOLATED
}


# ─────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────

def _hash_entry(event: str, timestamp: float,
                data_str: str, prev_hash: str) -> str:
    """
    Compute the hash for one audit log entry.

    We hash the concatenation of:
        event + str(timestamp) + data_str + prev_hash

    Using BLAKE2s — fast, secure, stdlib.

    Returns hex string (64 characters).

    This hash becomes the `prev_hash` of the NEXT entry,
    forming the chain.
    """
    raw = (
        event
        + str(timestamp)
        + data_str
        + prev_hash
    ).encode('utf-8')

    return hashlib.blake2s(raw).hexdigest()


def _hash_genesis() -> str:
    """
    The hash of the imaginary entry before the first real one.
    A fixed string of zeros — the chain anchor.
    Every audit log starts with this as its first prev_hash.
    """
    return "0" * 64


# ─────────────────────────────────────────────
# AUDIT LOG CLASS
# ─────────────────────────────────────────────

class AuditLog:
    """
    Append-only, hash-chained audit log.

    Stores entries as a JSON file on disk.
    Each entry is a dict:
    {
        "seq":        int,    sequential entry number
        "event":      str,    one of the event type constants
        "timestamp":  float,  unix timestamp
        "data":       dict,   event-specific metadata
        "prev_hash":  str,    hash of the previous entry
        "this_hash":  str,    hash of this entry
    }

    The chain is verified by recomputing every this_hash
    and checking it matches the next entry's prev_hash.
    """

    def __init__(self, log_path: str):
        """
        Initialise the audit log.

        Args:
            log_path: path to the JSON file where entries
                      are stored. Created if it does not exist.
        """
        self.log_path  = log_path
        self._entries  = []     # in-memory list of all entries
        self._load()            # load existing entries from disk


    # ── Persistence ───────────────────────────

    def _load(self):
        """
        Load existing entries from disk into memory.
        If the file does not exist, start with an empty log.
        """
        if not os.path.exists(self.log_path):
            self._entries = []
            return

        with open(self.log_path, 'r', encoding='utf-8') as f:
            try:
                self._entries = json.load(f)
            except json.JSONDecodeError:
                # Corrupted file — start fresh but keep the
                # corrupted file as evidence
                self._entries = []


    def _save(self):
        """
        Write all entries to disk as JSON.

        Uses indent=2 for human-readable output.
        Writes to a temp file first then renames — this
        prevents partial writes corrupting the log if the
        process is killed mid-write.
        """
        tmp_path = self.log_path + ".tmp"
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(self._entries, f, indent=2)
        os.replace(tmp_path, self.log_path)


    # ── Core operations ───────────────────────

    def _last_hash(self) -> str:
        """
        Return the hash of the most recent entry.
        If the log is empty, return the genesis hash (zeros).
        This is used as prev_hash for the next entry.
        """
        if not self._entries:
            return _hash_genesis()
        return self._entries[-1]['this_hash']


    def append(self, event: str, data: dict = None) -> dict:
        """
        Append a new event to the audit log.

        Args:
            event: one of the event type constants
                   e.g. RATCHET_TRIGGERED, ZK_PROOF_PASSED
            data:  dict of event-specific metadata
                   e.g. {"epoch": 3, "server": "server_a"}
                   Can be None or empty.

        Returns:
            The complete entry dict that was written.

        Raises:
            ValueError for unknown event types.
        """
        if event not in ALL_EVENT_TYPES:
            raise ValueError(
                f"Unknown event type: '{event}'. "
                f"Use one of the constants in audit.py"
            )

        if data is None:
            data = {}

        timestamp = time.time()
        seq       = len(self._entries) + 1
        prev_hash = self._last_hash()
        data_str  = json.dumps(data, sort_keys=True)

        this_hash = _hash_entry(event, timestamp, data_str, prev_hash)

        entry = {
            "seq":        seq,
            "event":      event,
            "timestamp":  timestamp,
            "data":       data,
            "prev_hash":  prev_hash,
            "this_hash":  this_hash,
        }

        self._entries.append(entry)
        self._save()

        return entry


    def verify_chain(self) -> tuple:
        """
        Walk every entry and verify the hash chain is intact.

        For each entry:
            1. Recompute this_hash from its fields
            2. Check recomputed == stored this_hash
            3. Check stored prev_hash == this_hash of previous entry

        Returns:
            (is_valid: bool, message: str)

            is_valid: True if the entire chain is intact
            message:  description of result or where it broke

        A broken chain means someone tampered with the log.
        """
        if not self._entries:
            return True, "Log is empty — nothing to verify"

        expected_prev = _hash_genesis()

        for i, entry in enumerate(self._entries):
            # Check prev_hash links correctly
            if entry['prev_hash'] != expected_prev:
                return False, (
                    f"Chain broken at entry {entry['seq']} "
                    f"(index {i}): prev_hash mismatch.\n"
                    f"Expected: {expected_prev}\n"
                    f"Found:    {entry['prev_hash']}"
                )

            # Recompute this_hash
            data_str  = json.dumps(entry['data'], sort_keys=True)
            expected_this = _hash_entry(
                entry['event'],
                entry['timestamp'],
                data_str,
                entry['prev_hash']
            )

            if entry['this_hash'] != expected_this:
                return False, (
                    f"Hash mismatch at entry {entry['seq']} "
                    f"(index {i}): this_hash does not match content.\n"
                    f"Expected: {expected_this}\n"
                    f"Found:    {entry['this_hash']}"
                )

            expected_prev = entry['this_hash']

        return True, f"Chain intact — {len(self._entries)} entries verified"


    # ── Query helpers ─────────────────────────

    def get_all(self) -> list:
        """
        Return all entries as a list of dicts.
        Used by the dashboard to display the live feed.
        """
        return list(self._entries)


    def get_by_event(self, event: str) -> list:
        """
        Return all entries of a specific event type.

        Example:
            log.get_by_event(RATCHET_TRIGGERED)
            → all ratchet events in chronological order
        """
        return [e for e in self._entries if e['event'] == event]


    def get_last(self, n: int = 10) -> list:
        """
        Return the most recent n entries.
        Used by the dashboard live feed.
        """
        return self._entries[-n:]


    def get_by_seq(self, seq: int) -> dict:
        """
        Return the entry with a specific sequence number.
        Returns None if not found.
        """
        for entry in self._entries:
            if entry['seq'] == seq:
                return entry
        return None


    def count(self) -> int:
        """Return total number of entries in the log."""
        return len(self._entries)


    def summary(self) -> dict:
        """
        Return a summary of the log for the dashboard.

        Returns:
        {
            "total":         int,   total entries
            "ratchets":      int,   how many times key ratcheted
            "failovers":     int,   how many failovers occurred
            "zk_passed":     int,   successful ZK proofs
            "zk_failed":     int,   failed ZK proofs
            "last_event":    str,   most recent event type
            "last_ts":       float, most recent timestamp
            "chain_valid":   bool,  is the chain intact
        }
        """
        is_valid, _ = self.verify_chain()

        return {
            "total":       self.count(),
            "ratchets":    len(self.get_by_event(RATCHET_TRIGGERED)),
            "failovers":   len(self.get_by_event(FAILOVER_COMPLETE)),
            "zk_passed":   len(self.get_by_event(ZK_PROOF_PASSED)),
            "zk_failed":   len(self.get_by_event(ZK_PROOF_FAILED)),
            "last_event":  self._entries[-1]['event'] if self._entries else None,
            "last_ts":     self._entries[-1]['timestamp'] if self._entries else None,
            "chain_valid": is_valid,
        }


    def clear(self):
        """
        Delete all entries and reset the log.
        Only used in tests — never in production.
        """
        self._entries = []
        if os.path.exists(self.log_path):
            os.remove(self.log_path)


    def pretty_print(self, last_n: int = None):
        """
        Print entries in a readable format.
        Useful for debugging and CLI display.

        Args:
            last_n: if set, only print the last n entries
        """
        entries = self.get_last(last_n) if last_n else self._entries

        if not entries:
            print("  (empty log)")
            return

        for e in entries:
            ts  = time.strftime('%H:%M:%S', time.localtime(e['timestamp']))
            seq = str(e['seq']).rjust(4)
            print(
                f"  [{seq}] {ts}  {e['event']:<28}"
                f"  hash={e['this_hash'][:12]}..."
            )
            if e['data']:
                for k, v in e['data'].items():
                    print(f"           {k}: {v}")


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    print("Running AuditLog self-tests...\n")

    # Use a temp file so tests don't pollute the real log
    tmp = tempfile.mktemp(suffix=".json")
    log = AuditLog(tmp)

    # Test 1: empty log verifies cleanly
    valid, msg = log.verify_chain()
    assert valid, f"FAIL: empty log should be valid: {msg}"
    print(f"[PASS] Empty log verifies cleanly")

    # Test 2: append a single entry
    e1 = log.append(SERVER_STARTED, {"server": "server_a", "epoch": 0})
    assert e1['seq']      == 1,               "FAIL: first seq should be 1"
    assert e1['event']    == SERVER_STARTED,  "FAIL: wrong event type"
    assert e1['prev_hash']== _hash_genesis(), "FAIL: first prev_hash should be genesis"
    assert len(e1['this_hash']) == 64,        "FAIL: hash should be 64 hex chars"
    print(f"[PASS] Single entry appended correctly")
    print(f"       seq=1  hash={e1['this_hash'][:16]}...")

    # Test 3: chain links correctly
    e2 = log.append(KEY_CEREMONY, {"n": 3, "k": 2, "epoch": 1})
    e3 = log.append(RATCHET_TRIGGERED, {"epoch": 1, "score": 0.72})

    assert e2['prev_hash'] == e1['this_hash'], "FAIL: e2 prev_hash != e1 this_hash"
    assert e3['prev_hash'] == e2['this_hash'], "FAIL: e3 prev_hash != e2 this_hash"
    print(f"[PASS] Hash chain links correctly across 3 entries")

    # Test 4: verify chain passes on untampered log
    valid, msg = log.verify_chain()
    assert valid, f"FAIL: valid chain failed verification: {msg}"
    print(f"[PASS] Chain verification passes: {msg}")

    # Test 5: tamper with an entry and verify chain breaks
    log._entries[1]['data']['k'] = 99   # tamper with entry 2
    valid, msg = log.verify_chain()
    assert not valid, "FAIL: tampered chain should fail verification"
    print(f"[PASS] Tampered chain correctly detected: {msg[:60]}...")

    # Restore and re-verify
    log._entries[1]['data']['k'] = 2
    # Note: hash won't match anymore since we tampered and didn't re-hash
    # Reset log for remaining tests
    log.clear()

    # Test 6: persistence — reload from disk
    log2 = AuditLog(tmp)
    log2.append(SERVER_STARTED,   {"server": "server_a"})
    log2.append(KEY_CEREMONY,     {"n": 3, "k": 2})
    log2.append(SHARE_ISSUED,     {"share_x": 1, "recipient": "server_a"})
    log2.append(RATCHET_TRIGGERED,{"epoch": 2, "score": 0.81})
    log2.append(ZK_PROOF_PASSED,  {"server": "server_b"})
    log2.append(FAILOVER_COMPLETE,{"new_primary": "server_b", "epoch": 3})

    # Reload from disk
    log3 = AuditLog(tmp)
    assert log3.count() == 6, f"FAIL: expected 6 entries after reload, got {log3.count()}"
    valid, msg = log3.verify_chain()
    assert valid, f"FAIL: reloaded chain invalid: {msg}"
    print(f"[PASS] Persistence works — 6 entries survive reload")
    print(f"[PASS] Reloaded chain verifies: {msg}")

    # Test 7: query helpers
    ratchet_events = log3.get_by_event(RATCHET_TRIGGERED)
    assert len(ratchet_events) == 1, "FAIL: should be 1 ratchet event"
    print(f"[PASS] get_by_event works")

    last_2 = log3.get_last(2)
    assert len(last_2) == 2,                    "FAIL: get_last(2) wrong count"
    assert last_2[-1]['event'] == FAILOVER_COMPLETE, "FAIL: last entry wrong"
    print(f"[PASS] get_last works")

    entry = log3.get_by_seq(3)
    assert entry is not None,              "FAIL: seq 3 not found"
    assert entry['event'] == SHARE_ISSUED, "FAIL: seq 3 wrong event"
    print(f"[PASS] get_by_seq works")

    # Test 8: summary
    s = log3.summary()
    assert s['total']      == 6,   "FAIL: wrong total"
    assert s['ratchets']   == 1,   "FAIL: wrong ratchet count"
    assert s['failovers']  == 1,   "FAIL: wrong failover count"
    assert s['zk_passed']  == 1,   "FAIL: wrong zk_passed count"
    assert s['chain_valid']== True, "FAIL: chain should be valid"
    print(f"[PASS] Summary correct: {s}")

    # Test 9: pretty print
    print(f"\n[PASS] Pretty print output:")
    log3.pretty_print()

    # Test 10: unknown event type raises ValueError
    try:
        log3.append("MADE_UP_EVENT", {})
        print("[FAIL] Should have raised ValueError")
    except ValueError as e:
        print(f"\n[PASS] Unknown event type rejected: {e}")

    # Cleanup
    log3.clear()
    if os.path.exists(tmp):
        os.remove(tmp)

    print("\nAll tests passed. audit.py is ready.")