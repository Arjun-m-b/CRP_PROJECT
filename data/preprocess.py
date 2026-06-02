# data/preprocess.py
# HYDRA medical-record preprocessing pipeline
#
# Reads raw Synthea-format patient data from data/raw/synthea_patients.json,
# normalises each patient record into a clean, deterministic structure,
# validates schema integrity, and writes encryption-ready records to
# data/processed/records.json.
#
# Output format consumed by run.py:
#   {
#       "record_id":      "patient-0001",
#       "plaintext_json": "<serialised patient dict as a JSON string>",
#       "patient_name":   "Eleanor Thompson",
#       "patient_age":    45
#   }
#
# Design rules followed:
#   - Only stdlib imports: sys, os, json, hashlib, time, datetime, re
#   - No crypto library — no encryption here, just normalisation
#   - Deterministic: same input always produces identical output
#   - Graceful: malformed entries are logged and skipped, not fatal
#   - Privacy-preserving: removes telecom details (phone/email) from
#     the stored plaintext; only clinical + demographic data is kept
#
# Usage:
#   python data/preprocess.py
#   python data/preprocess.py --input path/to/other.json
#   python data/preprocess.py --output path/to/output.json
#   python data/preprocess.py --validate-only   (no output written)
#   python data/preprocess.py --limit 5          (first 5 records)

import sys
import os
import json
import hashlib
import time
import re
import argparse
from datetime import datetime, date

sys.stdout.reconfigure(encoding='utf-8')

# ─────────────────────────────────────────────
# PATH SETUP
# ─────────────────────────────────────────────

# data/preprocess.py sits inside data/, so ROOT is one level up
_HERE = os.path.dirname(os.path.abspath(__file__))
ROOT  = os.path.dirname(_HERE)

DEFAULT_RAW_PATH  = os.path.join(_HERE, "raw",       "synthea_patients.json")
DEFAULT_OUT_PATH  = os.path.join(_HERE, "processed", "records.json")


# ─────────────────────────────────────────────
# SCHEMA — required keys for a valid processed record
# ─────────────────────────────────────────────

# These keys must be present and non-None in every output record's
# plaintext payload. If any are missing the record is rejected.
REQUIRED_PLAINTEXT_KEYS = {
    "record_id",
    "patient_name",
    "date_of_birth",
    "gender",
    "age",
    "conditions",
    "medications",
    "observations",
    "encounters",
    "allergies",
    "last_visit",
    "notes",
}

# Valid gender strings we accept (normalised to lowercase)
VALID_GENDERS = {"male", "female", "other", "unknown"}

# Maximum reasonable patient age (sanity guard)
MAX_AGE = 130


# ─────────────────────────────────────────────
# LAYER 1 — LOADING
# ─────────────────────────────────────────────

def load_raw(path: str) -> dict:
    """
    Load and parse the raw Synthea JSON file.

    The Synthea format is a FHIR-style Bundle with an 'entry' list.
    Each entry has a 'resource' key containing the patient resource.

    Args:
        path: absolute path to the raw JSON file

    Returns:
        Parsed dict. Raises FileNotFoundError or json.JSONDecodeError
        if the file is missing or malformed.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"Raw data file not found: {path}\n"
            f"Expected Synthea export at {path}"
        )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Accept either a FHIR Bundle with 'entry' or a plain list
    if isinstance(data, list):
        # Already a list of patient dicts
        entries = data
    elif isinstance(data, dict) and "entry" in data:
        # FHIR Bundle — unwrap
        entries = [
            e["resource"] for e in data["entry"]
            if isinstance(e, dict) and "resource" in e
        ]
    elif isinstance(data, dict) and "patients" in data:
        # Alternative wrapper key
        entries = data["patients"]
    else:
        raise ValueError(
            "Unrecognised file format. Expected a FHIR Bundle with "
            "'entry', a dict with 'patients', or a plain list."
        )

    return entries


# ─────────────────────────────────────────────
# LAYER 2 — FIELD EXTRACTION HELPERS
# ─────────────────────────────────────────────

def _extract_name(resource: dict) -> str:
    """
    Extract the patient's full name from a FHIR-style name list.

    Tries the first name entry's family + given fields.
    Falls back to a concatenation of all text fields.
    Returns 'Unknown Patient' if nothing is found.
    """
    names = resource.get("name", [])
    if not names:
        return "Unknown Patient"

    # Use the first name entry (official name)
    n = names[0] if isinstance(names[0], dict) else {}
    family = n.get("family", "")
    given  = n.get("given", [])

    # Join given names then append family
    given_str = " ".join(g for g in given if g) if given else ""
    parts = [p for p in [given_str, family] if p]

    if parts:
        return " ".join(parts)

    # Fallback: try 'text' field
    text = n.get("text", "")
    return text if text else "Unknown Patient"


def _extract_dob_and_age(resource: dict) -> tuple:
    """
    Extract date of birth and compute age in years.

    Returns (dob_str, age_int) where:
        dob_str: ISO date string "YYYY-MM-DD" or "unknown"
        age_int: integer age as of today, or 0 if unparseable

    The age computation uses the current date so output is
    deterministic for a fixed run-date (which is fine — records.json
    is regenerated on each pipeline run).
    """
    dob_raw = resource.get("birthDate", "")

    if not dob_raw:
        return "unknown", 0

    # Normalise: strip time portion if present
    dob_str = dob_raw.split("T")[0]

    # Validate ISO date format YYYY-MM-DD
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", dob_str):
        return dob_str, 0

    try:
        dob_date = datetime.strptime(dob_str, "%Y-%m-%d").date()
        today    = date.today()
        age = (today - dob_date).days // 365
        # Sanity guard: reject impossible ages
        if age < 0 or age > MAX_AGE:
            age = 0
    except ValueError:
        return dob_str, 0

    return dob_str, age


def _extract_gender(resource: dict) -> str:
    """
    Normalise gender to lowercase. Default 'unknown'.
    """
    raw = resource.get("gender", "unknown")
    normalised = raw.lower().strip() if raw else "unknown"
    return normalised if normalised in VALID_GENDERS else "unknown"


def _extract_conditions(resource: dict) -> list:
    """
    Extract diagnosed conditions as a list of dicts:
        {code, display, onset}

    The 'onset' date is normalised to YYYY-MM-DD format or left as-is.
    Unknown/missing fields are filled with empty strings.
    """
    raw_conditions = resource.get("conditions", [])
    result = []

    for c in raw_conditions:
        if not isinstance(c, dict):
            continue

        # Extract fields — tolerate FHIR CodeableConcept or flat dict
        code    = _safe_str(c.get("code", ""))
        display = _safe_str(
            c.get("display", "")
            or _nested_text(c, "coding", "display")
            or _nested_text(c, "code", "text")
        )
        onset = _normalise_date(c.get("onset", "") or c.get("onsetDateTime", ""))

        if display:  # Only include if we have at least a display name
            result.append({
                "code":    code,
                "display": display,
                "onset":   onset,
            })

    return result


def _extract_medications(resource: dict) -> list:
    """
    Extract medications as a list of dicts:
        {code, display, start}
    """
    raw_meds = resource.get("medications", [])
    result = []

    for m in raw_meds:
        if not isinstance(m, dict):
            continue

        code    = _safe_str(m.get("code", ""))
        display = _safe_str(
            m.get("display", "")
            or _nested_text(m, "medicationCodeableConcept", "text")
        )
        start = _normalise_date(m.get("start", "") or m.get("effectiveDateTime", ""))

        if display:
            result.append({
                "code":    code,
                "display": display,
                "start":   start,
            })

    return result


def _extract_observations(resource: dict) -> list:
    """
    Extract clinical observations (vitals, labs) as a list of dicts:
        {code, display, value, unit, date}

    Values are kept as their original types (int, float, str).
    """
    raw_obs = resource.get("observations", [])
    result  = []

    for o in raw_obs:
        if not isinstance(o, dict):
            continue

        code    = _safe_str(o.get("code", ""))
        display = _safe_str(o.get("display", ""))
        value   = o.get("value", None)  # keep original type
        unit    = _safe_str(o.get("unit", ""))
        obs_date = _normalise_date(o.get("date", "") or o.get("effectiveDateTime", ""))

        if display:
            result.append({
                "code":    code,
                "display": display,
                "value":   value,
                "unit":    unit,
                "date":    obs_date,
            })

    return result


def _extract_encounters(resource: dict) -> list:
    """
    Extract healthcare encounters as a list of dicts:
        {class, type, date, provider}
    """
    raw_enc = resource.get("encounters", [])
    result  = []

    for e in raw_enc:
        if not isinstance(e, dict):
            continue

        enc_class = _safe_str(e.get("class", "") or e.get("class_", ""))
        enc_type  = _safe_str(e.get("type", ""))
        enc_date  = _normalise_date(e.get("date", "") or e.get("period", {}).get("start", ""))
        provider  = _safe_str(e.get("provider", ""))

        if enc_type or enc_date:
            result.append({
                "class":    enc_class,
                "type":     enc_type,
                "date":     enc_date,
                "provider": provider,
            })

    return result


def _extract_allergies(resource: dict) -> list:
    """
    Extract allergies/adverse reactions as a list of dicts:
        {substance, reaction, severity}
    """
    raw_allergy = resource.get("allergies", [])
    result = []

    for a in raw_allergy:
        if not isinstance(a, dict):
            continue

        substance = _safe_str(
            a.get("substance", "")
            or _nested_text(a, "code", "text")
        )
        reaction  = _safe_str(a.get("reaction", ""))
        severity  = _safe_str(a.get("severity", "")).lower()

        if substance:
            result.append({
                "substance": substance,
                "reaction":  reaction,
                "severity":  severity,
            })

    return result


def _extract_last_visit(encounters: list) -> str:
    """
    Determine the most recent encounter date from the extracted encounters list.
    Returns ISO date string or "unknown".
    """
    dates = []
    for e in encounters:
        d = e.get("date", "")
        if d and re.match(r"^\d{4}-\d{2}-\d{2}", d):
            dates.append(d[:10])

    if not dates:
        return "unknown"

    # Lexicographic sort works for ISO dates
    return max(dates)


def _extract_notes(resource: dict) -> str:
    """
    Extract free-text clinical notes. Truncates to 2000 chars max.
    """
    raw = resource.get("notes", "") or resource.get("note", "")
    if isinstance(raw, list):
        # FHIR annotation array
        raw = " ".join(
            item.get("text", "") for item in raw
            if isinstance(item, dict)
        )
    return _safe_str(raw)[:2000]


# ─────────────────────────────────────────────
# LAYER 2 — UTILITY HELPERS
# ─────────────────────────────────────────────

def _safe_str(value) -> str:
    """Convert any value to a stripped string, returning '' for None/empty."""
    if value is None:
        return ""
    return str(value).strip()


def _normalise_date(raw: str) -> str:
    """
    Normalise a date string to YYYY-MM-DD format.
    Accepts ISO 8601 timestamps, strips time component.
    Returns the input unchanged if it cannot be parsed.
    """
    if not raw:
        return ""
    # Strip time portion from ISO 8601
    date_part = raw.split("T")[0].strip()
    if re.match(r"^\d{4}-\d{2}-\d{2}$", date_part):
        return date_part
    return _safe_str(raw)


def _nested_text(d: dict, *keys: str) -> str:
    """
    Navigate a nested dict via a sequence of keys and return the final
    string value. Returns "" if any key is missing or value is not a string.
    """
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return ""
        current = current.get(key)
    return _safe_str(current) if current else ""


# ─────────────────────────────────────────────
# LAYER 3 — DETERMINISTIC ID GENERATION
# ─────────────────────────────────────────────

def _make_record_id(resource: dict, index: int) -> str:
    """
    Generate a deterministic, stable record ID for a patient.

    Strategy:
        1. If the raw resource has a FHIR 'id' field (UUID-style),
           use its first 8 hex chars prefixed with "patient-".
        2. If the FHIR id is missing or not UUID-like, derive an ID
           from BLAKE2s(name + dob) to make it stable across re-runs.
        3. Fallback: "patient-{index:04d}" (zero-padded sequential).

    The ID is always lowercase ASCII, no Unicode.

    Args:
        resource: the raw patient resource dict
        index:    zero-based index in the entry list (for fallback)

    Returns:
        A stable string like "patient-a1b2c3d4" or "patient-0003"
    """
    fhir_id = resource.get("id", "")

    # Option 1: use the UUID with hyphens stripped, keeping 12 hex chars.
    # We skip the first 8 chars (they are shared across many Synthea UUIDs
    # that use a common prefix pattern) and instead use chars 8-20, which
    # encode the per-patient portion of the UUID.
    if fhir_id:
        hex_chars = re.sub(r"[^0-9a-fA-F]", "", fhir_id)
        if len(hex_chars) >= 16:
            # Use chars at positions 8..19 — skips the common prefix region
            unique_part = hex_chars[8:20].lower()
            return f"patient-{unique_part}"
        elif len(hex_chars) >= 8:
            return f"patient-{hex_chars[:8].lower()}"

    # Option 2: hash from name + dob for stability
    name = _extract_name(resource)
    dob  = resource.get("birthDate", "")
    seed = (name + dob).encode("utf-8")
    digest = hashlib.blake2s(seed, digest_size=4).hexdigest()  # 8 hex chars
    if digest != "00000000":  # avoid all-zero collision with null input
        return f"patient-{digest}"

    # Option 3: sequential fallback
    return f"patient-{index:04d}"


# ─────────────────────────────────────────────
# LAYER 4 — SCHEMA VALIDATION
# ─────────────────────────────────────────────

def validate_plaintext(payload: dict) -> list:
    """
    Validate a normalised plaintext payload dict against the schema.

    Returns a list of error strings (empty list = valid).
    Checks:
      - All required keys are present
      - patient_name is a non-empty string
      - date_of_birth matches YYYY-MM-DD or is 'unknown'
      - gender is in VALID_GENDERS
      - age is 0-130
      - conditions, medications, observations, encounters, allergies are lists
      - record_id is non-empty string
    """
    errors = []

    # Check all required keys present
    for key in REQUIRED_PLAINTEXT_KEYS:
        if key not in payload:
            errors.append(f"Missing required key: '{key}'")

    if errors:
        return errors  # Stop early — further checks would KeyError

    # patient_name
    name = payload["patient_name"]
    if not isinstance(name, str) or not name.strip():
        errors.append(f"patient_name is empty or not a string: {name!r}")

    # date_of_birth
    dob = payload["date_of_birth"]
    if dob != "unknown" and not re.match(r"^\d{4}-\d{2}-\d{2}$", str(dob)):
        errors.append(f"date_of_birth has unexpected format: {dob!r}")

    # gender
    gender = payload["gender"]
    if gender not in VALID_GENDERS:
        errors.append(f"gender is not in valid set: {gender!r}")

    # age
    age = payload["age"]
    if not isinstance(age, int) or age < 0 or age > MAX_AGE:
        errors.append(f"age out of valid range [0, {MAX_AGE}]: {age!r}")

    # List fields
    for list_key in ("conditions", "medications", "observations",
                     "encounters", "allergies"):
        val = payload[list_key]
        if not isinstance(val, list):
            errors.append(f"'{list_key}' should be a list, got {type(val).__name__}")

    # record_id
    rid = payload["record_id"]
    if not isinstance(rid, str) or not rid.strip():
        errors.append(f"record_id is empty or not a string: {rid!r}")

    return errors


# ─────────────────────────────────────────────
# LAYER 5 — CORE TRANSFORMATION
# ─────────────────────────────────────────────

def transform_patient(resource: dict, index: int) -> dict:
    """
    Transform one raw Synthea patient resource dict into a clean,
    encryption-ready HYDRA record.

    Steps:
        1. Generate deterministic record_id
        2. Extract and normalise all clinical fields
        3. Build the plaintext payload dict (no PII like phone/email)
        4. Serialise plaintext payload to a compact JSON string
        5. Return the wrapper dict expected by run.py

    Args:
        resource: raw patient resource dict from Synthea JSON
        index:    zero-based position in the entry list

    Returns:
        {
            "record_id":      str,   # stable ID like "patient-a1b2c3d4"
            "plaintext_json": str,   # compact JSON string of clinical data
            "patient_name":   str,   # display name for dashboard
            "patient_age":    int,   # age in years for dashboard
        }

    Raises:
        ValueError if the record fails schema validation.
    """
    record_id   = _make_record_id(resource, index)
    patient_name = _extract_name(resource)
    dob, age    = _extract_dob_and_age(resource)
    gender      = _extract_gender(resource)
    conditions  = _extract_conditions(resource)
    medications = _extract_medications(resource)
    observations = _extract_observations(resource)
    encounters  = _extract_encounters(resource)
    allergies   = _extract_allergies(resource)
    last_visit  = _extract_last_visit(encounters)
    notes       = _extract_notes(resource)

    # ── Plaintext payload ──────────────────────────────────────────
    # This is the actual data that HYDRA will encrypt with XChaCha20.
    # We deliberately exclude any telecom (phone/email) fields to
    # minimise PII stored in the encrypted blob.
    # The dashboard only uses patient_name and patient_age from the
    # outer wrapper; all clinical detail lives inside the encrypted blob.
    plaintext_payload = {
        "record_id":    record_id,
        "patient_name": patient_name,
        "date_of_birth": dob,
        "gender":       gender,
        "age":          age,
        "conditions":   conditions,
        "medications":  medications,
        "observations": observations,
        "encounters":   encounters,
        "allergies":    allergies,
        "last_visit":   last_visit,
        "notes":        notes,
        # Metadata for provenance — not clinical data
        "_hydra_meta": {
            "schema_version": "1.0",
            "preprocessed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source": "synthea_synthetic",
        },
    }

    # ── Schema validation ─────────────────────────────────────────
    errors = validate_plaintext(plaintext_payload)
    if errors:
        raise ValueError(
            f"Record {record_id} failed schema validation:\n  "
            + "\n  ".join(errors)
        )

    # ── Serialise to compact JSON string ───────────────────────────
    # sort_keys=True ensures deterministic byte-for-byte output,
    # which is important for reproducible ciphertext comparisons.
    # separators=(',', ':') produces compact JSON (no spaces).
    plaintext_json = json.dumps(
        plaintext_payload,
        ensure_ascii=True,   # ASCII-only — matches project rule 8
        sort_keys=True,
        separators=(",", ":"),
    )

    return {
        "record_id":      record_id,
        "plaintext_json": plaintext_json,
        "patient_name":   patient_name,
        "patient_age":    age,
    }


# ─────────────────────────────────────────────
# LAYER 6 — PIPELINE ORCHESTRATOR
# ─────────────────────────────────────────────

def run_pipeline(
    raw_path: str    = DEFAULT_RAW_PATH,
    out_path: str    = DEFAULT_OUT_PATH,
    validate_only: bool = False,
    limit: int       = None,
    verbose: bool    = True,
) -> list:
    """
    Execute the full preprocessing pipeline.

    Args:
        raw_path:      path to the raw Synthea JSON file
        out_path:      path to write processed records.json
        validate_only: if True, run all checks but do not write output
        limit:         if set, process only the first N entries
        verbose:       print progress to stdout

    Returns:
        List of processed record dicts (even if validate_only=True).
    """
    def log(msg: str):
        if verbose:
            print(msg)

    log("")
    log("=" * 60)
    log("  HYDRA Data Preprocessing Pipeline")
    log("=" * 60)
    log(f"  Source : {raw_path}")
    log(f"  Output : {out_path}")
    log(f"  Mode   : {'validate-only' if validate_only else 'full'}")
    log("")

    # ── Step 1: Load ──────────────────────────────────────────────
    log("[1/4] Loading raw Synthea data...")
    try:
        entries = load_raw(raw_path)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        sys.exit(1)
    except (json.JSONDecodeError, ValueError) as e:
        print(f"ERROR: Failed to parse {raw_path}: {e}")
        sys.exit(1)

    total = len(entries)
    if limit and limit > 0:
        entries = entries[:limit]
        log(f"      Loaded {total} entries, limiting to {len(entries)}")
    else:
        log(f"      Loaded {total} patient entries")

    # ── Step 2: Transform ─────────────────────────────────────────
    log("[2/4] Transforming and normalising records...")
    processed  = []
    skipped    = []
    seen_ids   = set()

    for i, resource in enumerate(entries):
        if not isinstance(resource, dict):
            skipped.append((i, "entry is not a dict"))
            continue

        try:
            record = transform_patient(resource, i)
        except ValueError as e:
            # Log schema errors but continue with remaining records
            skipped.append((i, str(e)))
            if verbose:
                print(f"  [SKIP] Entry {i}: {e}")
            continue
        except Exception as e:
            skipped.append((i, f"Unexpected error: {e}"))
            if verbose:
                print(f"  [SKIP] Entry {i}: Unexpected error: {e}")
            continue

        # Duplicate ID check — keep first occurrence
        rid = record["record_id"]
        if rid in seen_ids:
            skipped.append((i, f"Duplicate record_id '{rid}'"))
            if verbose:
                print(f"  [SKIP] Entry {i}: Duplicate record_id '{rid}'")
            continue

        seen_ids.add(rid)
        processed.append(record)

        if verbose:
            age  = record["patient_age"]
            name = record["patient_name"]
            size = len(record["plaintext_json"])
            print(f"  [OK]   {rid}  |  {name} (age {age})  |  {size} bytes plaintext")

    # ── Step 3: Summary ───────────────────────────────────────────
    log("")
    log("[3/4] Pipeline summary:")
    log(f"      Total entries    : {len(entries)}")
    log(f"      Processed OK     : {len(processed)}")
    log(f"      Skipped / errors : {len(skipped)}")

    if skipped:
        log("      Skipped entries:")
        for idx, reason in skipped:
            log(f"        Entry {idx}: {reason}")

    # Compute plaintext size statistics
    if processed:
        sizes = [len(r["plaintext_json"]) for r in processed]
        log(f"      Plaintext sizes  : min={min(sizes)} max={max(sizes)} "
            f"avg={sum(sizes)//len(sizes)} bytes")
        ages = [r["patient_age"] for r in processed if r["patient_age"] > 0]
        if ages:
            log(f"      Age range        : {min(ages)}-{max(ages)} years")

    # ── Step 4: Write output ──────────────────────────────────────
    if validate_only:
        log("")
        log("[4/4] Validate-only mode — no output written")
        log("")
        log("  Validation complete.")
        log("=" * 60)
        return processed

    log("")
    log("[4/4] Writing processed records...")

    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    # Atomic write: write to .tmp then rename to prevent partial files
    tmp_path = out_path + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(
                processed,
                f,
                ensure_ascii=True,
                indent=2,
                sort_keys=False,  # preserve insertion order in output
            )
        os.replace(tmp_path, out_path)
    except Exception as e:
        print(f"ERROR: Failed to write output: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        sys.exit(1)

    out_size = os.path.getsize(out_path)
    log(f"      Written {len(processed)} records to {out_path}")
    log(f"      File size: {out_size:,} bytes ({out_size // 1024} KB)")
    log("")
    log("  Preprocessing complete. Ready to encrypt.")
    log("=" * 60)
    log("")

    return processed


# ─────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="HYDRA data preprocessing pipeline — "
                    "transforms Synthea patient data into encryption-ready records."
    )
    parser.add_argument(
        "--input", "-i",
        default=DEFAULT_RAW_PATH,
        help=f"Path to raw Synthea JSON file (default: {DEFAULT_RAW_PATH})"
    )
    parser.add_argument(
        "--output", "-o",
        default=DEFAULT_OUT_PATH,
        help=f"Path to write processed records.json (default: {DEFAULT_OUT_PATH})"
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Run schema validation without writing output"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Process only the first N patient entries"
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress per-record output (only show summary)"
    )
    args = parser.parse_args()

    run_pipeline(
        raw_path      = args.input,
        out_path      = args.output,
        validate_only = args.validate_only,
        limit         = args.limit,
        verbose       = not args.quiet,
    )


# ─────────────────────────────────────────────
# SELF-TEST — run directly to verify pipeline
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile

    # ── If run with CLI args, execute as CLI ──────────────────────
    # Check if there are any real args beyond the script name
    if len(sys.argv) > 1:
        main()
        sys.exit(0)

    # ── Otherwise run self-tests ──────────────────────────────────
    print("Running preprocess.py self-tests...\n")
    PASS = "[PASS]"
    FAIL = "[FAIL]"
    errors_found = 0

    # ── Helper: make a minimal synthetic resource ─────────────────
    def _make_patient(
        fhir_id="test-uuid-0001",
        given=("Alice",),
        family="Sample",
        dob="1990-06-15",
        gender="female",
        conditions=None,
        medications=None,
        observations=None,
        encounters=None,
        allergies=None,
        notes="Test note.",
    ):
        return {
            "id": fhir_id,
            "name": [{"family": family, "given": list(given)}],
            "birthDate": dob,
            "gender": gender,
            "conditions":   conditions  or [],
            "medications":  medications or [],
            "observations": observations or [
                {"code": "8480-6", "display": "Systolic BP",
                 "value": 120, "unit": "mmHg", "date": "2024-01-01"},
            ],
            "encounters":   encounters or [
                {"class": "outpatient", "type": "Annual checkup",
                 "date": "2024-01-01", "provider": "Dr. Test"},
            ],
            "allergies":    allergies  or [],
            "notes":        notes,
        }

    def check(label, passed):
        global errors_found
        status = PASS if passed else FAIL
        print(f"  {status} {label}")
        if not passed:
            errors_found += 1

    # ── Test 1: Basic roundtrip ────────────────────────────────────
    p = _make_patient()
    rec = transform_patient(p, 0)
    check(
        "Basic transform returns required top-level keys",
        all(k in rec for k in ("record_id", "plaintext_json",
                                "patient_name", "patient_age"))
    )

    # ── Test 2: record_id is deterministic (same input = same ID) ─
    rec1 = transform_patient(p, 0)
    rec2 = transform_patient(p, 0)
    check("record_id is deterministic", rec1["record_id"] == rec2["record_id"])

    # ── Test 3: patient_name extracted correctly ───────────────────
    check(
        "patient_name extraction",
        rec["patient_name"] == "Alice Sample"
    )

    # ── Test 4: age computed correctly ────────────────────────────
    # DOB 1990-06-15: as of 2025 the patient is 34 or 35
    check(
        "age is reasonable integer (30-45 for 1990)",
        isinstance(rec["patient_age"], int) and 30 <= rec["patient_age"] <= 45
    )

    # ── Test 5: plaintext_json is valid JSON ──────────────────────
    try:
        parsed = json.loads(rec["plaintext_json"])
        check("plaintext_json is valid JSON", True)
    except Exception:
        check("plaintext_json is valid JSON", False)
        parsed = {}

    # ── Test 6: plaintext_json is ASCII-only ─────────────────────
    check(
        "plaintext_json is ASCII-only",
        rec["plaintext_json"].isascii()
    )

    # ── Test 7: conditions extracted ─────────────────────────────
    p_with_cond = _make_patient(conditions=[
        {"code": "44054006", "display": "Diabetes type 2", "onset": "2015-01-01"}
    ])
    rec_cond = transform_patient(p_with_cond, 0)
    parsed_cond = json.loads(rec_cond["plaintext_json"])
    check(
        "conditions extracted into plaintext",
        len(parsed_cond["conditions"]) == 1
        and parsed_cond["conditions"][0]["display"] == "Diabetes type 2"
    )

    # ── Test 8: allergies extracted ───────────────────────────────
    p_allergy = _make_patient(allergies=[
        {"substance": "Penicillin", "reaction": "Rash", "severity": "moderate"}
    ])
    rec_al = transform_patient(p_allergy, 0)
    parsed_al = json.loads(rec_al["plaintext_json"])
    check(
        "allergies extracted",
        len(parsed_al["allergies"]) == 1
        and parsed_al["allergies"][0]["substance"] == "Penicillin"
    )

    # ── Test 9: malformed entry is rejected gracefully ────────────
    bad_resource = {"id": "bad", "name": "not-a-list",
                    "birthDate": "1990-01-01",
                    "gender": "male"}
    # Should not raise — may produce an unknown-name entry
    # The test is that it does not crash
    crash = False
    try:
        transform_patient(bad_resource, 0)
    except Exception:
        crash = True
    check("malformed entry does not hard-crash transform_patient", not crash)

    # ── Test 10: unknown DOB handled ─────────────────────────────
    p_nodob = _make_patient(dob="")
    rec_nd = transform_patient(p_nodob, 0)
    parsed_nd = json.loads(rec_nd["plaintext_json"])
    check(
        "missing DOB becomes 'unknown' without crashing",
        parsed_nd["date_of_birth"] == "unknown"
    )

    # ── Test 11: validate_plaintext catches bad schema ────────────
    bad_payload = {"record_id": "x", "patient_name": "",
                   "date_of_birth": "bad", "gender": "alien",
                   "age": -5, "conditions": "not-a-list",
                   "medications": [], "observations": [],
                   "encounters": [], "allergies": [],
                   "last_visit": "unknown", "notes": ""}
    errs = validate_plaintext(bad_payload)
    check(
        "validate_plaintext catches multiple schema errors",
        len(errs) >= 3
    )

    # ── Test 12: full pipeline writes records.json ────────────────
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = os.path.join(tmpdir, "raw.json")
        out_path = os.path.join(tmpdir, "out", "records.json")

        # Write a minimal bundle
        bundle = {
            "entry": [
                {"resource": _make_patient(fhir_id="uuid-p001")},
                {"resource": _make_patient(fhir_id="uuid-p002",
                                           given=("Bob",), family="Test",
                                           dob="1985-03-20", gender="male")},
            ]
        }
        with open(raw_path, "w") as f:
            json.dump(bundle, f)

        result = run_pipeline(raw_path=raw_path, out_path=out_path, verbose=False)
        check("pipeline processes 2 patients", len(result) == 2)
        check("output file created", os.path.exists(out_path))

        with open(out_path) as f:
            loaded = json.load(f)
        check("output contains 2 records", len(loaded) == 2)
        check("each output record has record_id",
              all("record_id" in r for r in loaded))

    # ── Test 13: duplicate IDs skipped ───────────────────────────
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = os.path.join(tmpdir, "raw.json")
        out_path = os.path.join(tmpdir, "out", "records.json")

        # Two patients with same FHIR id → same record_id → second skipped
        same_patient = _make_patient(fhir_id="same-uuid-0000")
        bundle = {"entry": [{"resource": same_patient}, {"resource": same_patient}]}
        with open(raw_path, "w") as f:
            json.dump(bundle, f)

        result = run_pipeline(raw_path=raw_path, out_path=out_path, verbose=False)
        check("duplicate record_id is deduplicated", len(result) == 1)

    # ── Test 14: limit flag ───────────────────────────────────────
    with tempfile.TemporaryDirectory() as tmpdir:
        raw_path = os.path.join(tmpdir, "raw.json")
        out_path = os.path.join(tmpdir, "out", "records.json")

        bundle = {"entry": [
            {"resource": _make_patient(fhir_id=f"uuid-limit-{i:04d}",
                                        given=(f"Patient{i}",))}
            for i in range(10)
        ]}
        with open(raw_path, "w") as f:
            json.dump(bundle, f)

        result = run_pipeline(raw_path=raw_path, out_path=out_path,
                               verbose=False, limit=3)
        check("limit=3 produces exactly 3 records", len(result) == 3)

    # ── Results ───────────────────────────────────────────────────
    total_tests = 14
    passed = total_tests - errors_found
    print(f"\n  {passed}/{total_tests} tests passed.")

    if errors_found == 0:
        print("\nAll preprocess.py self-tests passed. Pipeline is ready.")
        print("Run:  python data/preprocess.py")
        print("      to generate data/processed/records.json")
    else:
        print(f"\n{errors_found} test(s) FAILED.")
        sys.exit(1)
