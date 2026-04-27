"""
Centralized cryptographic utilities.

All hash operations in the project route through this module.
Changing the hash algorithm here changes it everywhere.
"""

import hashlib
import json


HASH_ALGORITHM = "sha256"


def canonical_json(obj: dict) -> str:
    """Produce a deterministic JSON string from a dict.

    Uses sorted keys and no extra whitespace so the same logical
    content always yields the same byte sequence — a prerequisite
    for reproducible hashing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def compute_hash(obj: dict) -> str:
    """Return the hex-encoded SHA-256 of the canonical JSON of *obj*."""
    raw = canonical_json(obj)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def hash_string(data: str) -> str:
    """SHA-256 hex digest of an arbitrary string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()
