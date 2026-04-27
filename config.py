"""
Project-wide configuration constants.

Paths are relative to the project root.  Every module that needs
a path imports it from here so nothing is hard-coded in two places.
"""

import os

# Root of the project (directory that contains this file)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Persistent data directory
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# Default audit log path
AUDIT_LOG_PATH = os.path.join(DATA_DIR, "audit_log.jsonl")

# Genesis hash — the prev_hash for the very first entry
GENESIS_HASH = "0" * 64

# Sandbox defaults
SANDBOX_TIMEOUT = 5          # seconds
SANDBOX_MAX_OUTPUT = 10_000  # characters of stdout captured


def ensure_data_dir():
    """Create the data directory if it does not exist."""
    os.makedirs(DATA_DIR, exist_ok=True)
