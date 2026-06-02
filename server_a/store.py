# server_a/store.py
# Encrypted record store for Server A
# Only stdlib used: sqlite3, os, time, sys

import sys
import sqlite3
import os
import time
sys.stdout.reconfigure(encoding='utf-8')

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# Default database path for Server A
DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(__file__), "server_a.db"
)


# ─────────────────────────────────────────────
# STORE CLASS
# ─────────────────────────────────────────────

class EncryptedStore:
    """
    SQLite-backed store for encrypted records.

    Each record is stored as:
        - A unique string ID
        - The key epoch it was encrypted under
        - The XChaCha20 nonce (24 bytes)
        - The ciphertext (variable length)
        - The BLAKE2s MAC tag (32 bytes)
        - Created and updated timestamps

    The epoch column is critical for re-encryption —
    after a ratchet, all records at epoch N are pulled,
    decrypted with K_n, re-encrypted with K_n+1,
    and updated to epoch N+1.

    Usage:
        store = EncryptedStore()
        store.save("patient-001", 1, nonce, ciphertext, tag)
        record = store.get("patient-001")
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        """
        Initialise the store and create the table if needed.

        Args:
            db_path: path to the SQLite database file
        """
        self.db_path = db_path
        self._init_db()


    # ── Database setup ─────────────────────────

    def _get_conn(self) -> sqlite3.Connection:
        """
        Open and return a database connection.

        Uses check_same_thread=False so the same store
        instance can be used across Flask request threads.

        Row factory set to sqlite3.Row so columns are
        accessible by name: row['nonce'] not row[2].
        """
        conn = sqlite3.connect(
            self.db_path,
            check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        return conn


    def _init_db(self):
        """
        Create the records table if it does not exist.

        Also creates an index on epoch for fast re-encryption
        queries — when the ratchet fires we need all records
        at epoch N immediately.
        """
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS records (
                    id          TEXT    PRIMARY KEY,
                    epoch       INTEGER NOT NULL,
                    nonce       BLOB    NOT NULL,
                    ciphertext  BLOB    NOT NULL,
                    mac_tag     BLOB    NOT NULL,
                    created_at  REAL    NOT NULL,
                    updated_at  REAL    NOT NULL
                )
            """)

            # Index on epoch for fast ratchet re-encryption
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_epoch
                ON records (epoch)
            """)

            conn.commit()
        finally:
            conn.close()


    # ── Core CRUD ──────────────────────────────

    def save(self, record_id: str, epoch: int,
             nonce: bytes, ciphertext: bytes,
             mac_tag: bytes) -> bool:
        """
        Save an encrypted record to the store.

        If a record with this ID already exists,
        it is replaced (upsert behaviour).

        Args:
            record_id:  unique string identifier
                        e.g. "patient-001"
            epoch:      key epoch used to encrypt
                        e.g. 1
            nonce:      24-byte XChaCha20 nonce
            ciphertext: encrypted data bytes
            mac_tag:    32-byte BLAKE2s MAC tag

        Returns:
            True on success, False on failure
        """
        now = time.time()
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT INTO records
                    (id, epoch, nonce, ciphertext, mac_tag,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    epoch      = excluded.epoch,
                    nonce      = excluded.nonce,
                    ciphertext = excluded.ciphertext,
                    mac_tag    = excluded.mac_tag,
                    updated_at = excluded.updated_at
            """, (
                record_id, epoch,
                nonce, ciphertext, mac_tag,
                now, now
            ))
            conn.commit()
            return True
        except sqlite3.Error as e:
            print(f"[store] save error: {e}")
            return False
        finally:
            conn.close()


    def get(self, record_id: str) -> dict:
        """
        Retrieve a single encrypted record by ID.

        Args:
            record_id: the record's unique identifier

        Returns:
            dict with keys:
                id, epoch, nonce, ciphertext, mac_tag,
                created_at, updated_at
            or None if not found
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM records WHERE id = ?",
                (record_id,)
            ).fetchone()

            if row is None:
                return None

            return {
                "id":         row["id"],
                "epoch":      row["epoch"],
                "nonce":      bytes(row["nonce"]),
                "ciphertext": bytes(row["ciphertext"]),
                "mac_tag":    bytes(row["mac_tag"]),
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        finally:
            conn.close()


    def get_all(self) -> list:
        """
        Retrieve all records.

        Returns list of dicts — same format as get().
        Used by the dashboard record explorer.
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM records ORDER BY created_at ASC"
            ).fetchall()

            return [
                {
                    "id":         row["id"],
                    "epoch":      row["epoch"],
                    "nonce":      bytes(row["nonce"]),
                    "ciphertext": bytes(row["ciphertext"]),
                    "mac_tag":    bytes(row["mac_tag"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()


    def get_all_by_epoch(self, epoch: int) -> list:
        """
        Retrieve all records encrypted under a specific epoch.

        This is the key method used during re-encryption.
        After a ratchet fires at epoch N:
            records = store.get_all_by_epoch(N)
            for r in records:
                pt = decrypt(K_n, r['nonce'], r['ciphertext'], r['mac_tag'])
                new_nonce, new_ct, new_tag = encrypt(K_n1, pt)
                store.update(r['id'], N+1, new_nonce, new_ct, new_tag)

        Args:
            epoch: the epoch number to filter by

        Returns:
            list of record dicts at that epoch
        """
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM records WHERE epoch = ? ORDER BY id",
                (epoch,)
            ).fetchall()

            return [
                {
                    "id":         row["id"],
                    "epoch":      row["epoch"],
                    "nonce":      bytes(row["nonce"]),
                    "ciphertext": bytes(row["ciphertext"]),
                    "mac_tag":    bytes(row["mac_tag"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
                for row in rows
            ]
        finally:
            conn.close()


    def update(self, record_id: str, new_epoch: int,
               new_nonce: bytes, new_ciphertext: bytes,
               new_mac_tag: bytes) -> bool:
        """
        Update an existing record with new ciphertext.

        Used exclusively by the re-encryption module after
        a ratchet. The record ID stays the same — only the
        epoch, nonce, ciphertext, and MAC tag change.

        Args:
            record_id:      existing record's ID
            new_epoch:      the new key epoch (N+1)
            new_nonce:      new 24-byte nonce
                            (always generate a fresh nonce
                             when re-encrypting)
            new_ciphertext: ciphertext under new key
            new_mac_tag:    MAC tag under new key

        Returns:
            True on success, False if record not found
            or on DB error
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute("""
                UPDATE records
                SET epoch      = ?,
                    nonce      = ?,
                    ciphertext = ?,
                    mac_tag    = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                new_epoch, new_nonce,
                new_ciphertext, new_mac_tag,
                time.time(), record_id
            ))
            conn.commit()

            # rowcount 0 means record_id did not exist
            return cursor.rowcount > 0

        except sqlite3.Error as e:
            print(f"[store] update error: {e}")
            return False
        finally:
            conn.close()


    def delete(self, record_id: str) -> bool:
        """
        Delete a single record by ID.

        Not used in normal operation — included for
        admin/test purposes only.

        Returns:
            True if deleted, False if not found
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM records WHERE id = ?",
                (record_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()


    # ── Stats + Dashboard helpers ──────────────

    def count(self) -> int:
        """Return total number of records in the store."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT COUNT(*) as c FROM records"
            ).fetchone()
            return row["c"]
        finally:
            conn.close()


    def count_by_epoch(self) -> dict:
        """
        Return count of records per epoch.

        Used by dashboard to show how many records are
        at each key epoch.

        Returns:
            {epoch: count} e.g. {1: 45, 2: 12}
        """
        conn = self._get_conn()
        try:
            rows = conn.execute("""
                SELECT epoch, COUNT(*) as c
                FROM records
                GROUP BY epoch
                ORDER BY epoch
            """).fetchall()
            return {row["epoch"]: row["c"] for row in rows}
        finally:
            conn.close()


    def get_current_epoch(self) -> int:
        """
        Return the highest epoch number in the store.

        This tells us what the current key epoch is.
        Returns 0 if the store is empty.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT MAX(epoch) as e FROM records"
            ).fetchone()
            return row["e"] if row["e"] is not None else 0
        finally:
            conn.close()


    def exists(self, record_id: str) -> bool:
        """Check if a record ID exists in the store."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT 1 FROM records WHERE id = ?",
                (record_id,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()


    def summary(self) -> dict:
        """
        Return store summary for the dashboard.

        Returns:
        {
            "total":          int,
            "current_epoch":  int,
            "by_epoch":       dict,
            "db_path":        str
        }
        """
        return {
            "total":         self.count(),
            "current_epoch": self.get_current_epoch(),
            "by_epoch":      self.count_by_epoch(),
            "db_path":       self.db_path,
        }


    def clear(self):
        """
        Delete all records. Only used in tests.
        Never call in production.
        """
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM records")
            conn.commit()
        finally:
            conn.close()


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile
    import sys
    # Add parent dir so we can import core
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.xchacha20 import encrypt, decrypt, generate_key

    print("Running EncryptedStore self-tests...\n")

    # Use a temp DB so tests don't affect real data
    tmp_db = tempfile.mktemp(suffix=".db")
    store  = EncryptedStore(db_path=tmp_db)

    # Test data — simulated patient records
    key    = generate_key()
    key2   = generate_key()   # simulated post-ratchet key

    records = [
        ("patient-001", b'{"name":"Alice","diagnosis":"Hypertension"}'),
        ("patient-002", b'{"name":"Bob","diagnosis":"Diabetes Type 2"}'),
        ("patient-003", b'{"name":"Carol","diagnosis":"Post-op cardiac"}'),
    ]

    # Test 1: save records at epoch 1
    print("[TEST] Saving 3 records at epoch 1...")
    for rid, plaintext in records:
        nonce, ct, tag = encrypt(key, plaintext)
        ok = store.save(rid, epoch=1,
                        nonce=nonce, ciphertext=ct, mac_tag=tag)
        assert ok, f"FAIL: save failed for {rid}"
    print(f"[PASS] 3 records saved at epoch 1")

    # Test 2: get returns correct record
    r = store.get("patient-001")
    assert r is not None,       "FAIL: record not found"
    assert r["epoch"] == 1,     "FAIL: wrong epoch"
    assert len(r["nonce"]) == 24, "FAIL: nonce wrong length"
    assert len(r["mac_tag"]) == 32, "FAIL: tag wrong length"
    pt = decrypt(key, r["nonce"], r["ciphertext"], r["mac_tag"])
    assert pt == records[0][1], "FAIL: decrypted content mismatch"
    print(f"[PASS] get() returns correct record")
    print(f"       Decrypted: {pt.decode()}")

    # Test 3: get non-existent returns None
    assert store.get("doesnt-exist") is None, \
        "FAIL: missing record should return None"
    print(f"[PASS] get() returns None for missing record")

    # Test 4: get_all returns all records
    all_records = store.get_all()
    assert len(all_records) == 3, \
        f"FAIL: expected 3 records, got {len(all_records)}"
    print(f"[PASS] get_all() returns all 3 records")

    # Test 5: get_all_by_epoch
    epoch1_records = store.get_all_by_epoch(1)
    assert len(epoch1_records) == 3, \
        f"FAIL: expected 3 epoch-1 records, got {len(epoch1_records)}"
    epoch2_records = store.get_all_by_epoch(2)
    assert len(epoch2_records) == 0, \
        "FAIL: should be 0 epoch-2 records before ratchet"
    print(f"[PASS] get_all_by_epoch() works correctly")

    # Test 6: simulate ratchet re-encryption
    # Decrypt all epoch-1 records, re-encrypt with key2 at epoch 2
    print(f"\n[TEST] Simulating ratchet: epoch 1 -> epoch 2...")
    for rec in epoch1_records:
        pt = decrypt(key, rec["nonce"], rec["ciphertext"], rec["mac_tag"])
        new_nonce, new_ct, new_tag = encrypt(key2, pt)
        ok = store.update(
            rec["id"], new_epoch=2,
            new_nonce=new_nonce,
            new_ciphertext=new_ct,
            new_mac_tag=new_tag
        )
        assert ok, f"FAIL: update failed for {rec['id']}"

    # Verify all records now at epoch 2
    epoch1_after = store.get_all_by_epoch(1)
    epoch2_after = store.get_all_by_epoch(2)
    assert len(epoch1_after) == 0, \
        "FAIL: no records should remain at epoch 1"
    assert len(epoch2_after) == 3, \
        "FAIL: all 3 records should be at epoch 2"
    print(f"[PASS] Re-encryption complete — all records at epoch 2")

    # Verify decryption works with new key
    r2 = store.get("patient-001")
    pt2 = decrypt(key2, r2["nonce"], r2["ciphertext"], r2["mac_tag"])
    assert pt2 == records[0][1], "FAIL: re-encrypted record decrypts incorrectly"
    print(f"[PASS] Re-encrypted records decrypt correctly with new key")

    # Verify old key no longer works
    try:
        decrypt(key, r2["nonce"], r2["ciphertext"], r2["mac_tag"])
        print("[FAIL] Old key should not decrypt re-encrypted record")
    except ValueError:
        print(f"[PASS] Old key correctly rejected after re-encryption")

    # Test 7: count and summary
    assert store.count() == 3, "FAIL: wrong count"
    assert store.get_current_epoch() == 2, "FAIL: wrong current epoch"
    by_epoch = store.count_by_epoch()
    assert by_epoch.get(2) == 3, "FAIL: wrong epoch-2 count"
    print(f"[PASS] count() and count_by_epoch() correct")

    s = store.summary()
    assert s["total"]         == 3, "FAIL: wrong summary total"
    assert s["current_epoch"] == 2, "FAIL: wrong summary epoch"
    print(f"[PASS] summary() correct: {s}")

    # Test 8: exists()
    assert store.exists("patient-001") == True,  "FAIL: should exist"
    assert store.exists("patient-999") == False, "FAIL: should not exist"
    print(f"[PASS] exists() works correctly")

    # Test 9: delete
    ok = store.delete("patient-003")
    assert ok == True,               "FAIL: delete should return True"
    assert store.count() == 2,       "FAIL: count should be 2 after delete"
    assert not store.exists("patient-003"), "FAIL: deleted record should not exist"
    print(f"[PASS] delete() works correctly")

    # Test 10: upsert — saving same ID updates the record
    nonce, ct, tag = encrypt(key2, b"updated data")
    store.save("patient-001", epoch=3,
               nonce=nonce, ciphertext=ct, mac_tag=tag)
    r_updated = store.get("patient-001")
    assert r_updated["epoch"] == 3, "FAIL: upsert should update epoch"
    pt_updated = decrypt(
        key2, r_updated["nonce"],
        r_updated["ciphertext"], r_updated["mac_tag"]
    )
    assert pt_updated == b"updated data", "FAIL: upsert content wrong"
    print(f"[PASS] upsert (save existing ID) updates record correctly")

    # Cleanup
    store.clear()
    if os.path.exists(tmp_db):
        os.remove(tmp_db)

    print("\nAll tests passed. store.py is ready.")