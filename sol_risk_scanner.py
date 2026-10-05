#!/usr/bin/env python3
import sys
import os

RISK_PATTERNS = [
    ("tx.origin", "HIGH", "Use of tx.origin for auth is dangerous."),
    ("delegatecall", "HIGH", "delegatecall can lead to code injection / storage corruption."),
    ("selfdestruct", "MEDIUM", "Contract can be destroyed; check who can call this."),
    ("reentrancyGuard", "INFO", "Reentrancy guard present; verify correct usage."),
    ("call.value(", "MEDIUM", "Low-level call with value; check reentrancy."),
    ("transfer(", "INFO", "Uses transfer; check gas assumptions."),
    ("approve(", "INFO", "ERC20 approve; check for race conditions."),
    ("onlyOwner", "INFO", "Owner-only function; check centralization."),
]

def scan_file(path: str):
    print(f"=== Scanning: {path} ===")
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return

    findings = []
    for pattern, severity, description in RISK_PATTERNS:
        if pattern in content:
            findings.append((pattern, severity, description))

    if not findings:
        print("[OK] No known patterns found.\n")
        return

    for pattern, severity, description in findings:
        print(f"[{severity}] Pattern '{pattern}' found.")
        print(f"       {description}")
    print()

def main():
    if len(sys.argv) < 2:
        print("Usage: python sol_risk_scanner.py <file.sol> [more.sol ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        if not os.path.isfile(path):
            print(f"[WARN] {path} is not a file.")
            continue
        scan_file(path)

if __name__ == "__main__":
    main()
