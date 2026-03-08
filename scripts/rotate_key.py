#!/usr/bin/env python3
"""
API Key Management Utility for Intelligence Analyzer.
Allows rotation, revocation, and listing of API keys via the Admin API.
"""

import os
import sys
import json
import requests
import argparse
from typing import Optional, Dict, Any
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

def get_headers():
    if not ADMIN_API_KEY:
        print("Error: ADMIN_API_KEY environment variable not set.")
        sys.exit(1)
    return {
        "X-Admin-Key": ADMIN_API_KEY,
        "Content-Type": "application/json"
    }

def list_keys(tenant_id: str):
    """List all API keys for a tenant."""
    url = f"{API_BASE_URL}/api/admin/tenants/{tenant_id}/api-keys"
    try:
        response = requests.get(url, headers=get_headers())
        response.raise_for_status()
        data = response.json()
        keys = data.get("api_keys", [])
        
        print(f"\nAPI Keys for Tenant: {tenant_id}")
        print("-" * 60)
        if not keys:
            print("No keys found.")
        for key in keys:
            status = "Active" if key.get("is_active", True) else "Revoked"
            print(f"ID: {key['id']} | Prefix: {key['key_prefix']} | Status: {status}")
        print("-" * 60)
    except Exception as e:
        print(f"Error listing keys: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Server response: {e.response.text}")

def rotate_key(key_id: str):
    """Rotate an API key."""
    url = f"{API_BASE_URL}/api/admin/api-keys/{key_id}/rotate"
    try:
        response = requests.post(url, headers=get_headers())
        response.raise_for_status()
        data = response.json()
        
        print("\n✅ API Key Rotated Successfully!")
        print("-" * 60)
        print(f"Key ID:     {data['id']}")
        print(f"New Key:    {data['api_key']}")
        print(f"Prefix:     {data['key_prefix']}")
        print("-" * 60)
        print("⚠️  IMPORTANT: Save this key now! It will not be shown again.")
        print("⚠️  The old secret is now invalid.")
    except Exception as e:
        print(f"Error rotating key: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Server response: {e.response.text}")

def revoke_key(key_id: str):
    """Revoke an API key."""
    url = f"{API_BASE_URL}/api/admin/api-keys/{key_id}"
    try:
        response = requests.delete(url, headers=get_headers())
        response.raise_for_status()
        print(f"\n✅ API Key {key_id} revoked successfully.")
    except Exception as e:
        print(f"Error revoking key: {e}")
        if hasattr(e, 'response') and e.response is not None:
            print(f"Server response: {e.response.text}")

def main():
    parser = argparse.ArgumentParser(description="Intelligence Analyzer API Key Management")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List command
    list_parser = subparsers.add_parser("list", help="List keys for a tenant")
    list_parser.add_argument("tenant_id", help="ID of the tenant")

    # Rotate command
    rotate_parser = subparsers.add_parser("rotate", help="Rotate an API key")
    rotate_parser.add_argument("key_id", help="ID of the key to rotate")

    # Revoke command
    revoke_parser = subparsers.add_parser("revoke", help="Revoke an API key")
    revoke_parser.add_argument("key_id", help="ID of the key to revoke")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "list":
        list_keys(args.tenant_id)
    elif args.command == "rotate":
        rotate_key(args.key_id)
    elif args.command == "revoke":
        revoke_key(args.key_id)

if __name__ == "__main__":
    main()
