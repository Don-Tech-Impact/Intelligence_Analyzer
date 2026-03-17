#!/usr/bin/env python3
"""
Production Readiness Verification Script.
Runs security scanning, code quality checks, and full unit/integration tests.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_step(name, command):
    print(f"\n" + "="*60)
    print(f"🚀 STEP: {name}")
    print("="*60)
    try:
        # result = subprocess.run(command, shell=True, check=True, capture_output=False)
        # Using shell=True for windows compatibility with pip/pytest binaries
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output = ""
        while True:
            line = process.stdout.readline()
            if not line: break
            print(f"  {line.strip()}")
            output += line
            
        process.wait()
        if process.returncode != 0:
            print(f"❌ {name} FAILED with exit code {process.returncode}")
            return False
        
        print(f"✅ {name} PASSED")
        return True
    except Exception as e:
        print(f"❌ Error running {name}: {e}")
        return False

def main():
    root = Path(__file__).parent.parent
    os.chdir(root)

    print("🛡️  INTELLIGENCE ANALYZER - PRODUCTION READINESS CHECK")
    print(f"Target Directory: {root}")
    
    steps = [
        ("Security Scan (Bandit)", "bandit -r src/ -ll"),
        ("Static Analysis (Flake8)", "flake8 src/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics"),
        ("Type Checking (Mypy)", "mypy src/"),
        ("Unit & Integration Tests (Pytest)", "pytest tests/ -v --cov=src --cov-report=term-missing")
    ]

    results = []
    for name, cmd in steps:
        success = run_step(name, cmd)
        results.append((name, success))

    print("\n" + "="*60)
    print("📊 FINAL VERIFICATION REPORT")
    print("="*60)
    
    all_passed = True
    for name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        if not success: all_passed = False
        print(f"{name:<40} {status}")

    if all_passed:
        print("\n🎉 ALL CHECKS PASSED! The application is ready for production.")
        sys.exit(0)
    else:
        print("\n⚠️  SOME CHECKS FAILED. Please review the output above and fix issues before pushing.")
        sys.exit(1)

if __name__ == "__main__":
    main()
