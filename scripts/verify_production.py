#!/usr/bin/env python3
"""
Production Readiness Verification Script.
Runs security scanning, code quality checks, and full unit/integration tests.
"""

import os
import subprocess
import sys
from pathlib import Path


def run_step(name, command):
    print("\n" + "=" * 60)
    print(f"STEP: {name}")
    print("=" * 60)
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        while True:
            line = process.stdout.readline()
            if not line:
                break
            print(f"  {line.strip()}")

        process.wait()
        if process.returncode != 0:
            print(f"[FAIL] {name} exited with code {process.returncode}")
            return False

        print(f"[PASS] {name} successful")
        return True
    except Exception as e:
        print(f"[ERROR] Error running {name}: {e}")
        return False


def main():
    root = Path(__file__).parent.parent
    os.chdir(root)

    print("INTELLIGENCE ANALYZER - PRODUCTION READINESS CHECK")
    print(f"Target Directory: {root}")

    steps = [
        ("Security Scan (Bandit)", "python -m bandit -c scripts/bandit.yaml -r src/ -ll"),
        ("Static Analysis (Flake8)", "python -m flake8 src/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics"),
        ("Type Checking (Mypy)", "python -m mypy src/ --ignore-missing-imports"),
        ("Unit & Integration Tests (Pytest)", "python -m pytest tests/ -v"),
    ]

    results = []
    for name, cmd in steps:
        success = run_step(name, cmd)
        results.append((name, success))

    print("\n" + "=" * 60)
    print("FINAL VERIFICATION REPORT")
    print("=" * 60)

    all_passed = True
    for name, success in results:
        status = "PASSED" if success else "FAILED"
        if not success:
            all_passed = False
        print(f"{name:<40} {status}")

    if all_passed:
        print("\nALL CHECKS PASSED! The application is ready for production.")
        sys.exit(0)
    else:
        print("\nSOME CHECKS FAILED. Please review the output above and fix issues before pushing.")
        sys.exit(1)


if __name__ == "__main__":
    main()
