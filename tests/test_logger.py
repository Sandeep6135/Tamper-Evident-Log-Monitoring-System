"""Tests for Tamper-Evident Logging System."""

import json
import os
import sys
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tamper_evident_log.logger import TamperEvidentLog, LogEntry
from tamper_evident_log.verifier import LogVerifier
from config import GENESIS_HASH


@pytest.fixture
def log_file(tmp_path):
    return str(tmp_path / "test.jsonl")


@pytest.fixture
def populated_log(log_file):
    log = TamperEvidentLog(log_file)
    log.append("SYSTEM", "init")
    log.append("AUTH", "login")
    log.append("CONFIG", "update")
    log.append("BACKUP", "backup")
    log.append("AUTH", "logout")
    return log_file


# ---- LogEntry ----

class TestLogEntry:
    def test_hash_deterministic(self):
        a = LogEntry(0, 1000.0, "TEST", "data", GENESIS_HASH)
        b = LogEntry(0, 1000.0, "TEST", "data", GENESIS_HASH)
        assert a.hash == b.hash

    def test_hash_changes_with_description(self):
        a = LogEntry(0, 1000.0, "TEST", "data1", GENESIS_HASH)
        b = LogEntry(0, 1000.0, "TEST", "data2", GENESIS_HASH)
        assert a.hash != b.hash

    def test_hash_changes_with_event_type(self):
        a = LogEntry(0, 1000.0, "AUTH", "data", GENESIS_HASH)
        b = LogEntry(0, 1000.0, "CONFIG", "data", GENESIS_HASH)
        assert a.hash != b.hash

    def test_hash_changes_with_index(self):
        a = LogEntry(0, 1000.0, "TEST", "data", GENESIS_HASH)
        b = LogEntry(1, 1000.0, "TEST", "data", GENESIS_HASH)
        assert a.hash != b.hash

    def test_dict_roundtrip(self):
        entry = LogEntry(0, 1000.0, "TEST", "data", GENESIS_HASH)
        restored = LogEntry.from_dict(entry.to_dict())
        assert entry.hash == restored.hash
        assert entry.event_type == restored.event_type

    def test_to_dict_has_all_fields(self):
        entry = LogEntry(0, 1000.0, "TEST", "data", GENESIS_HASH)
        d = entry.to_dict()
        for key in ("index", "timestamp", "event_type",
                     "description", "prev_hash", "hash"):
            assert key in d


# ---- TamperEvidentLog ----

class TestTamperEvidentLog:
    def test_create_empty(self, log_file):
        log = TamperEvidentLog(log_file)
        assert len(log) == 0

    def test_append_single(self, log_file):
        log = TamperEvidentLog(log_file)
        entry = log.append("AUTH", "login")
        assert entry.index == 0
        assert entry.prev_hash == GENESIS_HASH
        assert entry.event_type == "AUTH"

    def test_chain_linkage(self, log_file):
        log = TamperEvidentLog(log_file)
        e0 = log.append("A", "a")
        e1 = log.append("B", "b")
        e2 = log.append("C", "c")
        assert e1.prev_hash == e0.hash
        assert e2.prev_hash == e1.hash

    def test_persistence_across_reload(self, log_file):
        log1 = TamperEvidentLog(log_file)
        log1.append("X", "x1")
        log1.append("Y", "x2")
        log2 = TamperEvidentLog(log_file)
        assert len(log2) == 2
        assert log2[0].description == "x1"
        assert log2[1].description == "x2"

    def test_jsonl_format(self, log_file):
        log = TamperEvidentLog(log_file)
        log.append("TEST", "test entry")
        with open(log_file) as f:
            lines = f.readlines()
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert "hash" in parsed
        assert "event_type" in parsed

    def test_clear(self, log_file):
        log = TamperEvidentLog(log_file)
        log.append("A", "a")
        log.clear()
        assert len(log) == 0
        assert os.path.getsize(log_file) == 0


# ---- LogVerifier ----

class TestLogVerifier:
    def test_empty_log_valid(self, log_file):
        log = TamperEvidentLog(log_file)
        result = LogVerifier.verify_chain(log)
        assert result.is_valid
        assert result.total_entries == 0

    def test_valid_log(self, populated_log):
        result = LogVerifier.verify_file(populated_log)
        assert result.is_valid
        assert result.total_entries == 5

    def test_detect_modification(self, populated_log):
        with open(populated_log, "r") as f:
            lines = f.readlines()
        entry = json.loads(lines[2])
        entry["description"] = "TAMPERED"
        lines[2] = json.dumps(entry) + "\n"
        with open(populated_log, "w") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(populated_log)
        assert not result.is_valid
        assert result.failed_index == 2
        assert result.failure_type == "HASH_MISMATCH"

    def test_detect_deletion(self, populated_log):
        with open(populated_log, "r") as f:
            lines = f.readlines()
        del lines[1]
        with open(populated_log, "w") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(populated_log)
        assert not result.is_valid
        assert result.failed_index == 1

    def test_detect_reorder(self, populated_log):
        with open(populated_log, "r") as f:
            lines = f.readlines()
        lines[2], lines[3] = lines[3], lines[2]
        with open(populated_log, "w") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(populated_log)
        assert not result.is_valid

    def test_detect_insertion(self, populated_log):
        with open(populated_log, "r") as f:
            lines = f.readlines()
        fake = {"index": 2, "timestamp": 0.0, "event_type": "FAKE",
                "description": "FAKE", "prev_hash": "0" * 64,
                "hash": "f" * 64}
        lines.insert(2, json.dumps(fake) + "\n")
        with open(populated_log, "w") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(populated_log)
        assert not result.is_valid
        assert result.failed_index == 2

    def test_detect_first_entry_tamper(self, populated_log):
        with open(populated_log, "r") as f:
            lines = f.readlines()
        entry = json.loads(lines[0])
        entry["description"] = "TAMPERED GENESIS"
        lines[0] = json.dumps(entry) + "\n"
        with open(populated_log, "w") as f:
            f.writelines(lines)

        result = LogVerifier.verify_file(populated_log)
        assert not result.is_valid
        assert result.failed_index == 0
