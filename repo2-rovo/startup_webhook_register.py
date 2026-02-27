"""
Startup Webhook Registration
=============================
Registers Repo 2's webhook URL with Repo 1 on startup so that Repo 1
can send tenant lifecycle events (tenant.created / updated / deleted)
to this service.

WHY THIS IS NEEDED:
  Repo 1 only sends webhooks to a URL it knows about. It resolves the
  target URL in this priority order:
    1. Explicit URL stored in Redis via POST /admin/webhooks/configure
    2. Auto-derived: ${REPO2_URL}/api/admin/tenants/sync

  If neither is set, webhooks are silently dropped. This script ensures
  option 1 is always set when Repo 2 starts.

USAGE:
  Option A — Run as a one-shot script:
      python repo2-rovo/startup_webhook_register.py

  Option B — Call register_webhook() from src/main.py startup:
      from repo2_rovo.startup_webhook_register import register_webhook_on_startup
      register_webhook_on_startup()   # safe to call on every startup (idempotent)

ENVIRONMENT VARIABLES REQUIRED:
  REPO2_WEBHOOK_URL   — The full URL Repo 1 should POST to
                        e.g. http://repo2-host:8000/api/admin/tenants/sync
  REPO1_BASE_URL      — Repo 1 API base URL (also accepts REPO1_URL)
  ADMIN_KEY           — Shared admin key (also accepts ADMIN_API_KEY)
"""

import logging
import os
import sys
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------

def _repo1_base() -> str:
    return (
        os.getenv("REPO1_BASE_URL")
        or os.getenv("REPO1_URL")
        or "http://localhost:8080"
    ).rstrip("/")


def _admin_key() -> str:
    return (
        os.getenv("ADMIN_KEY")
        or os.getenv("ADMIN_API_KEY")
        or "changeme-admin-key"
    )


def _repo2_webhook_url() -> Optional[str]:
    return os.getenv("REPO2_WEBHOOK_URL", "").strip() or None


# ---------------------------------------------------------------------------
# Core registration logic
# ---------------------------------------------------------------------------

def register_webhook(
    webhook_url: Optional[str] = None,
    repo1_base: Optional[str] = None,
    admin_key: Optional[str] = None,
    timeout: float = 10.0,
) -> dict:
    """
    Register Repo 2's webhook URL with Repo 1.

    Args:
        webhook_url:  The URL Repo 1 should POST tenant events to.
                      Defaults to REPO2_WEBHOOK_URL env var.
        repo1_base:   Repo 1 API base URL. Defaults to REPO1_BASE_URL env var.
        admin_key:    Shared admin key. Defaults to ADMIN_KEY env var.
        timeout:      HTTP request timeout in seconds.

    Returns:
        Repo 1's response dict on success.

    Raises:
        ValueError: if webhook_url is not set.
        httpx.HTTPError: if the request fails.
    """
    webhook_url = webhook_url or _repo2_webhook_url()
    repo1_base = (repo1_base or _repo1_base()).rstrip("/")
    admin_key = admin_key or _admin_key()

    if not webhook_url:
        raise ValueError(
            "REPO2_WEBHOOK_URL environment variable is not set. "
            "Set it to e.g. http://repo2-host:8000/api/admin/tenants/sync"
        )

    url = f"{repo1_base}/admin/webhooks/configure"
    headers = {
        "X-Admin-Key": admin_key,
        "Content-Type": "application/json",
    }
    payload = {"webhook_url": webhook_url}

    logger.info(f"Registering webhook URL with Repo 1: {webhook_url}")
    logger.info(f"Repo 1 target: POST {url}")

    with httpx.Client(timeout=timeout) as client:
        response = client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

    logger.info(f"Webhook registered successfully: {data}")
    return data


def check_webhook_status(
    repo1_base: Optional[str] = None,
    admin_key: Optional[str] = None,
    timeout: float = 10.0,
) -> dict:
    """
    Fetch the current webhook configuration from Repo 1.

    Returns the Repo 1 response dict:
        {"webhook_url": "...", "status": "configured"|"not_configured", ...}
    """
    repo1_base = (repo1_base or _repo1_base()).rstrip("/")
    admin_key = admin_key or _admin_key()

    with httpx.Client(timeout=timeout) as client:
        response = client.get(
            f"{repo1_base}/admin/webhooks/status",
            headers={"X-Admin-Key": admin_key},
        )
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Startup-safe wrapper (retries, logs, never crashes the app)
# ---------------------------------------------------------------------------

def register_webhook_on_startup(
    retries: int = 3,
    retry_delay: float = 5.0,
) -> bool:
    """
    Register Repo 2's webhook URL with Repo 1, with retries.

    Designed to be called from src/main.py without crashing the app if
    Repo 1 is temporarily unavailable at startup.

    Returns True on success, False if all retries fail.

    Example usage in src/main.py:
        from repo2_rovo.startup_webhook_register import register_webhook_on_startup

        class SIEMAnalyzer:
            def start(self):
                register_webhook_on_startup()   # best-effort, never crashes
                ... rest of startup ...
    """
    webhook_url = _repo2_webhook_url()

    if not webhook_url:
        logger.warning(
            "REPO2_WEBHOOK_URL not set — skipping webhook registration. "
            "Repo 1 will use its auto-derived URL (REPO2_URL env var on Repo 1 side)."
        )
        return False

    for attempt in range(1, retries + 1):
        try:
            result = register_webhook(webhook_url)
            status = result.get("status", "unknown")
            logger.info(
                f"Webhook registration successful (attempt {attempt}/{retries}): "
                f"status={status}, url={webhook_url}"
            )
            return True

        except ValueError as exc:
            # Config problem — no point retrying
            logger.error(f"Webhook registration config error: {exc}")
            return False

        except httpx.HTTPStatusError as exc:
            logger.warning(
                f"Webhook registration HTTP error (attempt {attempt}/{retries}): "
                f"{exc.response.status_code} {exc.response.text}"
            )

        except Exception as exc:
            logger.warning(
                f"Webhook registration failed (attempt {attempt}/{retries}): {exc}"
            )

        if attempt < retries:
            logger.info(f"Retrying in {retry_delay}s...")
            time.sleep(retry_delay)

    logger.error(
        f"Webhook registration failed after {retries} attempts. "
        "Tenant sync webhooks from Repo 1 may not be delivered. "
        "Run startup_webhook_register.py manually once Repo 1 is available."
    )
    return False


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
    )

    # Show current state first
    print("\n=== Current webhook status (Repo 1) ===")
    try:
        status = check_webhook_status()
        print(f"  Status:      {status.get('status', 'unknown')}")
        print(f"  Webhook URL: {status.get('webhook_url', '(not set)')}")
        print(f"  Message:     {status.get('message', '')}")
    except Exception as exc:
        print(f"  Could not reach Repo 1: {exc}")

    # Register
    print("\n=== Registering webhook ===")
    webhook_url = _repo2_webhook_url()
    if not webhook_url:
        print(
            "ERROR: REPO2_WEBHOOK_URL is not set.\n"
            "Set it to e.g.: export REPO2_WEBHOOK_URL=http://repo2-host:8000/api/admin/tenants/sync"
        )
        sys.exit(1)

    print(f"  Webhook URL: {webhook_url}")
    print(f"  Repo 1 base: {_repo1_base()}")

    try:
        result = register_webhook(webhook_url)
        print(f"\n✅ Registered successfully: {result}")
    except httpx.HTTPStatusError as exc:
        print(f"\n❌ HTTP error: {exc.response.status_code} — {exc.response.text}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n❌ Error: {exc}")
        sys.exit(1)

    # Verify
    print("\n=== Verified webhook status ===")
    try:
        status = check_webhook_status()
        print(f"  Status:      {status.get('status')}")
        print(f"  Webhook URL: {status.get('webhook_url')}")
        print(f"\n✅ Repo 1 will now POST tenant events to: {status.get('webhook_url')}")
    except Exception as exc:
        print(f"  Verification failed: {exc}")


if __name__ == "__main__":
    main()
