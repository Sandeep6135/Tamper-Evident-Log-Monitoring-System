"""
Tamper-Evident Log — CLI Interface

Usage:
    python -m tamper_evident_log.cli append --type AUTH --desc "User logged in"
    python -m tamper_evident_log.cli append --type CONFIG --desc "Firewall updated" --file data/audit_log.jsonl
    python -m tamper_evident_log.cli verify
    python -m tamper_evident_log.cli show
    python -m tamper_evident_log.cli demo
"""

import argparse
import sys

from config import AUDIT_LOG_PATH
from tamper_evident_log.logger import TamperEvidentLog
from tamper_evident_log.verifier import LogVerifier


def main():
    parser = argparse.ArgumentParser(
        description="Tamper-Evident Audit Log CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # --- append ---
    ap = sub.add_parser("append", help="Append an entry to the audit log")
    ap.add_argument("--type", required=True, help="Event type (e.g. AUTH, CONFIG, BACKUP)")
    ap.add_argument("--desc", required=True, help="Event description")
    ap.add_argument("--file", default=AUDIT_LOG_PATH, help="Log file path")

    # --- verify ---
    vp = sub.add_parser("verify", help="Verify log integrity")
    vp.add_argument("--file", default=AUDIT_LOG_PATH, help="Log file path")

    # --- show ---
    sp = sub.add_parser("show", help="Display all log entries")
    sp.add_argument("--file", default=AUDIT_LOG_PATH, help="Log file path")

    # --- demo ---
    sub.add_parser("demo", help="Run tampering attack simulations")

    args = parser.parse_args()

    if args.command == "append":
        log = TamperEvidentLog(args.file)
        entry = log.append(args.type, args.desc)
        print(f"[OK] Entry {entry.index} appended.")
        print(f"     Type : {entry.event_type}")
        print(f"     Hash : {entry.hash[:24]}...")

    elif args.command == "verify":
        result = LogVerifier.verify_file(args.file)
        if result.is_valid:
            print(f"[VALID] Integrity verified. {result.total_entries} entries checked.")
        else:
            print(f"[TAMPERED] Integrity FAILED at entry {result.failed_index}")
            print(f"  Type   : {result.failure_type}")
            print(f"  Details: {result.details}")
            sys.exit(1)

    elif args.command == "show":
        log = TamperEvidentLog(args.file)
        entries = log.get_entries()
        if not entries:
            print("(empty log)")
            return
        for entry in entries:
            d = entry.to_dict()
            print(f"[{d['index']}] [{d['event_type']}] {d['description']}")
            print(f"     Hash : {d['hash'][:32]}...")
            print(f"     Prev : {d['prev_hash'][:32]}...")
            print()

    elif args.command == "demo":
        from tamper_evident_log.tamper_demo import TamperDemo
        demo = TamperDemo()
        demo.run_all()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
