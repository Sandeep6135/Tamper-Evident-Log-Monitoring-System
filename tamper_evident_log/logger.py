"""
Tamper-Evident Logging System — Core Logger

Each log entry contains:
    index, timestamp, event_type, description, prev_hash, hash

The hash is SHA-256 of the canonical JSON of all fields EXCEPT the hash
itself, ensuring any modification to any field invalidates the entry.

Storage: JSONL (one JSON object per line).
"""

import json
import time
import os
from typing import List, Optional

from utils.crypto import compute_hash
from config import GENESIS_HASH, AUDIT_LOG_PATH, ensure_data_dir


class LogEntry:
    """Single entry in the tamper-evident audit log."""

    __slots__ = ("index", "timestamp", "event_type", "description",
                 "prev_hash", "hash")

    def __init__(self, index: int, timestamp: float, event_type: str,
                 description: str, prev_hash: str, entry_hash: Optional[str] = None):
        self.index = index
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.prev_hash = prev_hash
        self.hash = entry_hash if entry_hash else self._compute_hash()

    def _compute_hash(self) -> str:
        """SHA-256 of canonical JSON of all fields except the hash itself."""
        return compute_hash(self._hashable_dict())

    def _hashable_dict(self) -> dict:
        """Fields that go into the hash computation."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict:
        """Full dict for serialization (includes the hash)."""
        d = self._hashable_dict()
        d["hash"] = self.hash
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "LogEntry":
        """Reconstruct WITHOUT recomputing hash — preserves stored value
        so the verifier can compare it against a fresh computation."""
        return cls(
            index=d["index"],
            timestamp=d["timestamp"],
            event_type=d["event_type"],
            description=d["description"],
            prev_hash=d["prev_hash"],
            entry_hash=d["hash"],
        )

    def __repr__(self):
        return (f"LogEntry(index={self.index}, event_type={self.event_type!r}, "
                f"hash={self.hash[:12]}...)")


class TamperEvidentLog:
    """Append-only audit log with SHA-256 hash chaining and JSONL persistence."""

    def __init__(self, filepath: str = AUDIT_LOG_PATH):
        self.filepath = filepath
        self.entries: List[LogEntry] = []
        ensure_data_dir()
        if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
            self._load()

    def _load(self):
        """Load existing entries from the JSONL file."""
        self.entries = []
        with open(self.filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    self.entries.append(LogEntry.from_dict(json.loads(line)))

    def append(self, event_type: str, description: str) -> LogEntry:
        """Append a new entry, chaining it to the previous entry's hash."""
        prev_hash = self.entries[-1].hash if self.entries else GENESIS_HASH
        index = len(self.entries)
        timestamp = time.time()
        entry = LogEntry(index, timestamp, event_type, description, prev_hash)
        self.entries.append(entry)

        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        return entry

    def get_entries(self) -> List[LogEntry]:
        """Return a copy of all entries."""
        return list(self.entries)

    def clear(self):
        """Remove all entries and truncate the file."""
        self.entries = []
        with open(self.filepath, "w", encoding="utf-8") as f:
            f.truncate(0)

    def __len__(self):
        return len(self.entries)

    def __getitem__(self, index):
        return self.entries[index]
