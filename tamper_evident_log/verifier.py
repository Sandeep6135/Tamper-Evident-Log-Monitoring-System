"""
Tamper-Evident Logging System — Verifier

Walks the hash chain and detects:
  - Data modification  (HASH_MISMATCH)
  - Entry deletion     (INDEX_DISCONTINUITY or CHAIN_BREAK)
  - Entry reordering   (INDEX_DISCONTINUITY or CHAIN_BREAK)
  - Entry insertion     (INDEX_DISCONTINUITY or CHAIN_BREAK)

Reports the EXACT index where the first failure occurs.
"""

from dataclasses import dataclass
from typing import Optional

from utils.crypto import compute_hash
from config import GENESIS_HASH
from tamper_evident_log.logger import LogEntry, TamperEvidentLog


@dataclass
class VerificationResult:
    """Structured result of a log integrity check."""
    is_valid: bool
    total_entries: int
    failed_index: Optional[int] = None
    failure_type: Optional[str] = None
    details: Optional[str] = None

    def __str__(self):
        if self.is_valid:
            return f"VALID — {self.total_entries} entries verified."
        return (
            f"TAMPERED at entry {self.failed_index}\n"
            f"  Type   : {self.failure_type}\n"
            f"  Details: {self.details}"
        )


class LogVerifier:
    """Verifies integrity of a TamperEvidentLog instance or JSONL file."""

    @staticmethod
    def verify_chain(log: TamperEvidentLog) -> VerificationResult:
        """Walk the chain, recompute every hash, and check linkage."""
        entries = log.get_entries()
        total = len(entries)

        if total == 0:
            return VerificationResult(is_valid=True, total_entries=0)

        for i, entry in enumerate(entries):
            # --- Check 1: Index continuity ---
            if entry.index != i:
                return VerificationResult(
                    is_valid=False,
                    total_entries=total,
                    failed_index=i,
                    failure_type="INDEX_DISCONTINUITY",
                    details=(
                        f"Expected index {i}, found {entry.index}. "
                        f"Indicates deletion, insertion, or reordering."
                    ),
                )

            # --- Check 2: Chain linkage ---
            expected_prev = GENESIS_HASH if i == 0 else entries[i - 1].hash
            if entry.prev_hash != expected_prev:
                return VerificationResult(
                    is_valid=False,
                    total_entries=total,
                    failed_index=i,
                    failure_type="CHAIN_BREAK",
                    details=(
                        f"Entry {i}: prev_hash does not match hash of entry {i - 1}. "
                        f"Possible insertion, deletion, or reordering."
                    ),
                )

            # --- Check 3: Hash recomputation ---
            recomputed = compute_hash({
                "index": entry.index,
                "timestamp": entry.timestamp,
                "event_type": entry.event_type,
                "description": entry.description,
                "prev_hash": entry.prev_hash,
            })
            if entry.hash != recomputed:
                return VerificationResult(
                    is_valid=False,
                    total_entries=total,
                    failed_index=i,
                    failure_type="HASH_MISMATCH",
                    details=(
                        f"Entry {i}: stored hash does not match recomputed hash. "
                        f"Data has been modified."
                    ),
                )

        return VerificationResult(is_valid=True, total_entries=total)

    @staticmethod
    def verify_file(filepath: str) -> VerificationResult:
        """Convenience: load a JSONL file and verify it."""
        log = TamperEvidentLog(filepath)
        return LogVerifier.verify_chain(log)
