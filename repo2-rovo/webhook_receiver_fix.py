"""
Webhook Receiver Fix
====================
Fixes the X-Admin-Key authentication on POST /api/admin/tenants/sync.

PROBLEM:
  `verify_admin_key` uses `Header(..., alias="X-Admin-Key")` — the ellipsis
  makes FastAPI treat the header as a *required schema field*. When Repo 1
  omits the header, FastAPI returns HTTP 422 (Unprocessable Entity) before
  our auth logic even runs. The Repo 1 contract mandates HTTP 401.

FIX:
  Change to `Header(None, ...)` so the header is optional at the FastAPI
  schema level, then validate it explicitly with a 401 response.

HOW TO APPLY:
  In src/api/admin_router.py, replace the `verify_admin_key` function
  with the corrected version below (copy from PATCHED_FUNCTION).

  Alternatively, run this file directly to print the patch instructions:
      python repo2-rovo/webhook_receiver_fix.py
"""

import os
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Request, HTTPException, status, Header, Depends
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PATCHED verify_admin_key — copy this into src/api/admin_router.py
# ---------------------------------------------------------------------------

def verify_admin_key_fixed(
    x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")
) -> str:
    """
    Validate X-Admin-Key header for incoming webhooks from Repo 1.

    Returns the key string on success.
    Raises HTTP 401 (not 422) when the header is missing or incorrect.

    This replaces the original `verify_admin_key` which used Header(...)
    causing FastAPI to return 422 when the header is absent entirely.
    """
    if not x_admin_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Admin-Key header",
            headers={"WWW-Authenticate": "X-Admin-Key"},
        )

    expected = (
        os.getenv("ADMIN_KEY")
        or os.getenv("ADMIN_API_KEY")
        or "changeme-admin-key"
    )

    if x_admin_key != expected:
        # Log the suffix for debugging without revealing the full key
        suffix = x_admin_key[-4:] if len(x_admin_key) >= 4 else "????"
        logger.warning(f"Webhook X-Admin-Key mismatch (received suffix: ...{suffix})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Admin-Key",
        )

    return x_admin_key


# ---------------------------------------------------------------------------
# Standalone fixed webhook router (for testing or Option B install)
# ---------------------------------------------------------------------------

webhook_fix_router = APIRouter(prefix="/api/admin", tags=["Webhook (Fixed)"])


@webhook_fix_router.post("/tenants/sync")
async def sync_tenant_fixed(request: Request):
    """
    Fixed webhook receiver for Repo 1 → Repo 2 tenant lifecycle events.

    Repo 1 contract:
        POST /api/admin/tenants/sync
        X-Admin-Key: <ADMIN_KEY>
        Body: {
            "event": "tenant.created|tenant.updated|tenant.deleted",
            "tenant": {"tenant_id": str, "name": str, "status": str},
            "timestamp": "<ISO 8601>"
        }

    Response:
        200 OK  → {"status": "ok", "event": ..., "tenant_id": ..., "action": ...}
        400     → invalid payload
        401     → missing or bad X-Admin-Key (NOT 422)

    Idempotent: safe to receive the same event multiple times.
    """
    # --- Auth: 401 (not 422) on missing/wrong key ---
    incoming_key = request.headers.get("X-Admin-Key", "")
    expected_key = (
        os.getenv("ADMIN_KEY")
        or os.getenv("ADMIN_API_KEY")
        or "changeme-admin-key"
    )

    if not incoming_key:
        logger.warning("[webhook] Received request without X-Admin-Key header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Admin-Key header",
            headers={"WWW-Authenticate": "X-Admin-Key"},
        )

    if incoming_key != expected_key:
        suffix = incoming_key[-4:] if len(incoming_key) >= 4 else "????"
        logger.warning(f"[webhook] X-Admin-Key mismatch (suffix: ...{suffix})")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Admin-Key",
        )

    # --- Parse body ---
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event = body.get("event", "")
    tenant_data = body.get("tenant", {})
    tenant_id = tenant_data.get("tenant_id", "")

    if not event or not tenant_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid payload: 'event' and 'tenant.tenant_id' are required",
        )

    logger.info(f"[webhook] event='{event}' tenant_id='{tenant_id}'")

    # --- Database operations ---
    try:
        from src.core.database import db_manager
        from src.models.database import Tenant

        with db_manager.session_scope() as db:
            existing = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()

            if event == "tenant.deleted":
                if existing:
                    existing.is_active = False
                    db.commit()
                    logger.info(f"[webhook] Tenant '{tenant_id}' soft-deleted")
                    return {
                        "status": "ok",
                        "event": event,
                        "tenant_id": tenant_id,
                        "action": "deactivated",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                # Idempotent: already gone is fine
                logger.info(f"[webhook] Delete for unknown tenant '{tenant_id}' — OK")
                return {
                    "status": "ok",
                    "event": event,
                    "tenant_id": tenant_id,
                    "action": "not_found_already_deleted",
                    "timestamp": datetime.utcnow().isoformat(),
                }

            # tenant.created or tenant.updated → upsert
            is_active = tenant_data.get("status", "active") == "active"
            tenant_name = tenant_data.get("name", tenant_id)

            if not existing:
                db.add(Tenant(tenant_id=tenant_id, name=tenant_name, is_active=is_active))
                action = "created"
            else:
                existing.name = tenant_name
                existing.is_active = is_active
                action = "updated"

            db.commit()
            logger.info(f"[webhook] Tenant '{tenant_id}' {action}")

    except Exception as exc:
        logger.error(f"[webhook] DB error for '{tenant_id}': {exc}", exc_info=True)
        # Return 200 — Repo 1 does not retry, so we must not block the pipeline.
        return {
            "status": "error",
            "event": event,
            "tenant_id": tenant_id,
            "detail": f"DB error (logged for recovery): {exc}",
            "timestamp": datetime.utcnow().isoformat(),
        }

    return {
        "status": "ok",
        "event": event,
        "tenant_id": tenant_id,
        "action": action,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Patch instructions printed when run directly
# ---------------------------------------------------------------------------

PATCH = """
=============================================================================
PATCH: src/api/admin_router.py  — verify_admin_key fix (422 → 401)
=============================================================================

Replace the existing `verify_admin_key` function (~line 50) with:

    def verify_admin_key(
        x_admin_key: Optional[str] = Header(None, alias="X-Admin-Key")
    ) -> str:
        if not x_admin_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing X-Admin-Key header",
                headers={"WWW-Authenticate": "X-Admin-Key"},
            )
        expected = _get_admin_key()
        if x_admin_key != expected:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid X-Admin-Key",
            )
        return x_admin_key

That's the complete fix. The route path and body handling are correct.
=============================================================================
"""

if __name__ == "__main__":
    print(PATCH)
