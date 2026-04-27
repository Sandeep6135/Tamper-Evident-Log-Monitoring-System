"""
Tamper-Evident Log — Attack Simulation Suite

Demonstrates four distinct attack vectors and verifies that the
system detects each one with exact failure localization.
"""

import json
import os
import tempfile

from tamper_evident_log.logger import TamperEvidentLog
from tamper_evident_log.verifier import LogVerifier


class TamperDemo:
    """Creates sample logs, tampers with them, and shows detection."""

    def __init__(self, work_dir: str = None):
        self.work_dir = work_dir or tempfile.mkdtemp(prefix="tamper_demo_")

    def _create_sample_log(self, filename: str) -> str:
        """Create a fresh 5-entry log and return its path."""
        filepath = os.path.join(self.work_dir, filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        log = TamperEvidentLog(filepath)
        log.append("SYSTEM", "System initialized")
        log.append("AUTH", "User admin authenticated via MFA")
        log.append("CONFIG", "Firewall rule updated: allow port 443")
        log.append("BACKUP", "Database backup completed successfully")
        log.append("AUTH", "User admin session terminated")
        return filepath

    # ---- Attack 1: Modify data ----
    def demo_modification(self) -> dict:
        """Tamper by changing an entry's description field."""
        filepath = self._create_sample_log("attack_modification.jsonl")
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        entry = json.loads(lines[2])
        entry["description"] = "MALICIOUS: All firewall rules deleted"
        lines[2] = json.dumps(entry) + "\n"

        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(filepath)
        return self._format(
            "Data Modification (entry 2 description changed)", result
        )

    # ---- Attack 2: Delete entry ----
    def demo_deletion(self) -> dict:
        """Tamper by removing entry 1 entirely."""
        filepath = self._create_sample_log("attack_deletion.jsonl")
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        del lines[1]
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(filepath)
        return self._format("Entry Deletion (removed entry 1)", result)

    # ---- Attack 3: Reorder entries ----
    def demo_reorder(self) -> dict:
        """Tamper by swapping entries 2 and 3."""
        filepath = self._create_sample_log("attack_reorder.jsonl")
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()
        lines[2], lines[3] = lines[3], lines[2]
        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(filepath)
        return self._format(
            "Entry Reordering (swapped entries 2 and 3)", result
        )

    # ---- Attack 4: Insert forged entry ----
    def demo_insertion(self) -> dict:
        """Tamper by inserting a forged entry at position 2."""
        filepath = self._create_sample_log("attack_insertion.jsonl")
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        fake = {
            "index": 2,
            "timestamp": 9999999999.0,
            "event_type": "FORGED",
            "description": "Unauthorized privilege escalation",
            "prev_hash": "0" * 64,
            "hash": "deadbeef" * 8,
        }
        lines.insert(2, json.dumps(fake) + "\n")

        with open(filepath, "w", encoding="utf-8") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(filepath)
        return self._format(
            "Entry Insertion (forged entry at index 2)", result
        )

    @staticmethod
    def _format(attack_name: str, result) -> dict:
        return {
            "attack": attack_name,
            "detected": not result.is_valid,
            "failed_index": result.failed_index,
            "failure_type": result.failure_type,
            "details": result.details,
        }

    def run_all(self):
        """Execute all attack simulations and print results."""
        print("=" * 70)
        print("  TAMPER-EVIDENT LOG — ATTACK SIMULATION SUITE")
        print("=" * 70)

        demos = [
            self.demo_modification,
            self.demo_deletion,
            self.demo_reorder,
            self.demo_insertion,
        ]

        all_detected = True
        for fn in demos:
            r = fn()
            tag = "DETECTED" if r["detected"] else "MISSED"
            if not r["detected"]:
                all_detected = False
            print(f"\n  [{tag}] {r['attack']}")
            print(f"    Failure Index : {r['failed_index']}")
            print(f"    Failure Type  : {r['failure_type']}")
            print(f"    Details       : {r['details']}")

        print()
        print("=" * 70)
        if all_detected:
            print("  RESULT: All 4/4 tampering attacks detected successfully.")
        else:
            print("  WARNING: Some attacks were NOT detected.")
        print("=" * 70)
