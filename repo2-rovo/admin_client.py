"""
Typed Repo 1 Admin API Client for Repo 2
=========================================

Provides a clean, typed Python interface over all Repo 1 admin endpoints
with correct parameter names (matching the Repo 1 integration contract).

KEY FIX vs src/api/admin_router.py proxy:
  The proxy's list_tenants() sends query param `page_size` but Repo 1's
  GET /admin/tenants expects `limit`. This client uses the correct names.

Usage:
    from repo2_rovo.admin_client import Repo1AdminClient

    client = Repo1AdminClient()
    token = client.login("superadmin@example.com", "SuperAdmin123!")
    tenants = client.list_tenants(token=token, limit=50)
    key = client.create_api_key(token, "acme_corp", name="Forwarder Key")
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

def _base_url() -> str:
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


# ---------------------------------------------------------------------------
# Response types
# ---------------------------------------------------------------------------

@dataclass
class LoginResponse:
    access_token: str
    token_type: str
    expires_in: int
    admin: Dict[str, Any]


@dataclass
class TenantSummary:
    id: str
    tenant_id: str
    name: str
    status: str
    created_at: str
    ip_count: int = 0
    api_key_count: int = 0


@dataclass
class ApiKeyCreated:
    id: str
    api_key: str          # Full key — only shown once!
    key_prefix: str
    name: str
    tenant_id: str
    permissions: Dict[str, bool]
    created_at: str
    expires_at: Optional[str]
    warning: str = ""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class Repo1AdminClient:
    """
    Typed client for Repo 1's admin API.

    Authentication: Prefers X-Admin-Key (machine-to-machine). Falls back to
    Bearer JWT when a token is passed explicitly.

    All methods raise httpx.HTTPStatusError on 4xx/5xx responses.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        admin_key: Optional[str] = None,
        timeout: float = 10.0,
    ):
        self.base_url = (base_url or _base_url()).rstrip("/")
        self.admin_key = admin_key or _admin_key()
        self.timeout = timeout

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _headers(self, token: Optional[str] = None) -> Dict[str, str]:
        """Build request headers. Bearer JWT takes precedence over X-Admin-Key."""
        h = {
            "Content-Type": "application/json",
            "X-Admin-Key": self.admin_key,
        }
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    def _get(
        self, path: str, params: Optional[Dict] = None, token: Optional[str] = None
    ) -> Any:
        url = f"{self.base_url}{path}"
        with httpx.Client(timeout=self.timeout) as c:
            r = c.get(url, headers=self._headers(token), params=params)
            r.raise_for_status()
            return r.json()

    def _post(
        self, path: str, body: Optional[Dict] = None, token: Optional[str] = None
    ) -> Any:
        url = f"{self.base_url}{path}"
        with httpx.Client(timeout=self.timeout) as c:
            r = c.post(url, headers=self._headers(token), json=body or {})
            r.raise_for_status()
            return r.json()

    def _put(
        self, path: str, body: Optional[Dict] = None, token: Optional[str] = None
    ) -> Any:
        url = f"{self.base_url}{path}"
        with httpx.Client(timeout=self.timeout) as c:
            r = c.put(url, headers=self._headers(token), json=body or {})
            r.raise_for_status()
            return r.json()

    def _delete(self, path: str, token: Optional[str] = None) -> Any:
        url = f"{self.base_url}{path}"
        with httpx.Client(timeout=self.timeout) as c:
            r = c.delete(url, headers=self._headers(token))
            r.raise_for_status()
            return r.json()

    # -------------------------------------------------------------------------
    # Auth
    # -------------------------------------------------------------------------

    def login(self, email: str, password: str) -> str:
        """
        Login to Repo 1 and return the JWT access token.

        Token expires in 3600 seconds. Refresh before expiry using login() again.
        """
        data = self._post("/admin/login", {"email": email, "password": password})
        token = data.get("access_token")
        if not token:
            raise ValueError(f"Login failed — no access_token in response: {data}")
        logger.info(f"Logged in as {email} (token expires in {data.get('expires_in', '?')}s)")
        return token

    def logout(self, token: str) -> Dict:
        """Invalidate a JWT token (adds to Repo 1's Redis blocklist)."""
        return self._post("/admin/logout", token=token)

    def get_jwt_config(self, token: str) -> Dict:
        """
        Fetch JWT algorithm metadata from Repo 1.

        Use GET /api/admin/config/verify-sync on Repo 2 side to confirm
        SECRET_KEY alignment without the secret crossing the wire.
        """
        return self._get("/admin/auth/jwt-public-config", token=token)

    # -------------------------------------------------------------------------
    # Tenants
    # -------------------------------------------------------------------------

    def list_tenants(
        self,
        token: Optional[str] = None,
        page: int = 1,
        limit: int = 20,           # NOTE: Repo 1 uses "limit" not "page_size"
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> Dict:
        """
        List tenants from Repo 1.

        NOTE: param name is `limit` (not `page_size`). The admin_router.py
        proxy incorrectly sends `page_size` — this client fixes that.
        """
        params: Dict[str, Any] = {"page": page, "limit": limit}
        if status:
            params["status"] = status
        if search:
            params["search"] = search
        return self._get("/admin/tenants", params=params, token=token)

    def get_tenant(self, tenant_id: str, token: Optional[str] = None) -> Dict:
        """Get full tenant detail including IP allowlist and API keys."""
        return self._get(f"/admin/tenants/{tenant_id}", token=token)

    def create_tenant(
        self,
        tenant_id: str,
        name: str,
        description: str = "",
        config: Optional[Dict] = None,
        token: Optional[str] = None,
    ) -> Dict:
        """
        Create a new tenant in Repo 1.

        Side effect: fires tenant.created webhook to Repo 2.

        tenant_id rules: 2–64 chars, only [a-zA-Z0-9_-]
        """
        body: Dict[str, Any] = {"tenant_id": tenant_id, "name": name}
        if description:
            body["description"] = description
        if config:
            body["config"] = config
        return self._post("/admin/tenants", body=body, token=token)

    def update_tenant(
        self,
        tenant_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,  # "active" | "suspended" | "deleted"
        config: Optional[Dict] = None,
        token: Optional[str] = None,
    ) -> Dict:
        """Update a tenant. Side effect: fires tenant.updated webhook."""
        body: Dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if status is not None:
            body["status"] = status
        if config is not None:
            body["config"] = config
        return self._put(f"/admin/tenants/{tenant_id}", body=body, token=token)

    def delete_tenant(self, tenant_id: str, token: Optional[str] = None) -> Dict:
        """Soft-delete a tenant. Side effect: fires tenant.deleted webhook."""
        return self._delete(f"/admin/tenants/{tenant_id}", token=token)

    # -------------------------------------------------------------------------
    # API Keys
    # -------------------------------------------------------------------------

    def create_api_key(
        self,
        tenant_id: str,
        name: str,
        ingest: bool = True,
        read: bool = False,
        expires_at: Optional[str] = None,  # ISO 8601 string or None
        token: Optional[str] = None,
    ) -> Dict:
        """
        Create an API key for a tenant.

        IMPORTANT: The full api_key value is returned only in this response.
        Store it immediately — subsequent calls only return the key_prefix.
        """
        body: Dict[str, Any] = {
            "name": name,
            "permissions": {"ingest": ingest, "read": read},
        }
        if expires_at:
            body["expires_at"] = expires_at
        return self._post(f"/admin/tenants/{tenant_id}/api-keys", body=body, token=token)

    def list_api_keys(self, tenant_id: str, token: Optional[str] = None) -> Dict:
        """List API keys for a tenant (full key value never returned in list)."""
        return self._get(f"/admin/tenants/{tenant_id}/api-keys", token=token)

    def revoke_api_key(self, key_id: str, token: Optional[str] = None) -> Dict:
        """Permanently delete an API key."""
        return self._delete(f"/admin/api-keys/{key_id}", token=token)

    def deactivate_api_key(self, key_id: str, token: Optional[str] = None) -> Dict:
        """Deactivate (not delete) an API key — keeps audit trail."""
        return self._put(
            f"/admin/api-keys/{key_id}", body={"is_active": False}, token=token
        )

    # -------------------------------------------------------------------------
    # IP Allowlist
    # -------------------------------------------------------------------------

    def list_ips(self, tenant_id: str, token: Optional[str] = None) -> Dict:
        """List IP allowlist entries for a tenant."""
        return self._get(f"/admin/tenants/{tenant_id}/ips", token=token)

    def add_ip(
        self,
        tenant_id: str,
        ip_range: str,
        description: str = "",
        is_active: bool = True,
        token: Optional[str] = None,
    ) -> Dict:
        """
        Add an IP or CIDR range to a tenant's allowlist.

        ip_range accepts: "1.2.3.4" (single) or "10.0.0.0/8" (CIDR).
        """
        return self._post(
            f"/admin/tenants/{tenant_id}/ips",
            body={"ip_range": ip_range, "description": description, "is_active": is_active},
            token=token,
        )

    def remove_ip(
        self, tenant_id: str, ip_id: str, token: Optional[str] = None
    ) -> Dict:
        """Remove an IP allowlist entry by its UUID."""
        return self._delete(f"/admin/tenants/{tenant_id}/ips/{ip_id}", token=token)

    # -------------------------------------------------------------------------
    # Users
    # -------------------------------------------------------------------------

    def list_users(
        self,
        token: Optional[str] = None,
        page: int = 1,
        limit: int = 20,
        tenant_id: Optional[str] = None,
    ) -> Dict:
        params: Dict[str, Any] = {"page": page, "limit": limit}
        if tenant_id:
            params["tenant_id"] = tenant_id
        return self._get("/admin/users", params=params, token=token)

    def create_user(
        self,
        tenant_id: str,
        email: str,
        username: str,
        password: str,
        role: str = "user",  # "admin" | "user" | "viewer"
        token: Optional[str] = None,
    ) -> Dict:
        """Create a user scoped to a tenant. Password min 8 chars."""
        return self._post(
            "/admin/users",
            body={
                "tenant_id": tenant_id,
                "email": email,
                "username": username,
                "password": password,
                "role": role,
            },
            token=token,
        )

    def delete_user(self, username: str, token: Optional[str] = None) -> Dict:
        """Soft-delete a user by username."""
        return self._delete(f"/admin/users/{username}", token=token)

    # -------------------------------------------------------------------------
    # Webhook configuration
    # -------------------------------------------------------------------------

    def configure_webhook(self, webhook_url: str, token: Optional[str] = None) -> Dict:
        """
        Set or override the webhook URL that Repo 1 sends tenant events to.

        Repo 2 should call this once on startup to ensure Repo 1 knows where
        to send tenant.created / tenant.updated / tenant.deleted events.
        """
        return self._post(
            "/admin/webhooks/configure",
            body={"webhook_url": webhook_url},
            token=token,
        )

    def get_webhook_status(self, token: Optional[str] = None) -> Dict:
        """Get the currently active webhook configuration from Repo 1."""
        return self._get("/admin/webhooks/status", token=token)

    def delete_webhook_override(self, token: Optional[str] = None) -> Dict:
        """Remove the explicit webhook URL override (reverts to auto-derived URL)."""
        return self._delete("/admin/webhooks/configure", token=token)

    # -------------------------------------------------------------------------
    # Audit log
    # -------------------------------------------------------------------------

    def get_audit_log(
        self,
        page: int = 1,
        limit: int = 50,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        token: Optional[str] = None,
    ) -> Dict:
        """
        Retrieve the admin audit log from Repo 1.

        action options: CREATE_TENANT, UPDATE_TENANT, DELETE_TENANT,
                        CREATE_API_KEY, DELETE_API_KEY, ADD_IP, REMOVE_IP,
                        CREATE_USER, DELETE_USER, CONFIGURE_WEBHOOK
        resource_type: tenant, api_key, user, ip, webhook
        """
        params: Dict[str, Any] = {"page": page, "limit": limit}
        if action:
            params["action"] = action
        if resource_type:
            params["resource_type"] = resource_type
        return self._get("/admin/audit-log", params=params, token=token)

    # -------------------------------------------------------------------------
    # Health / metrics
    # -------------------------------------------------------------------------

    def health(self) -> Dict:
        """GET /health — no auth required."""
        return self._get("/health")

    def ingestion_health(self) -> Dict:
        """GET /api/logs/health — no auth required."""
        return self._get("/api/logs/health")

    def metrics(self) -> str:
        """GET /metrics — returns Prometheus plain text."""
        url = f"{self.base_url}/metrics"
        with httpx.Client(timeout=self.timeout) as c:
            r = c.get(url)
            r.raise_for_status()
            return r.text

    # -------------------------------------------------------------------------
    # Convenience: full tenant provisioning flow
    # -------------------------------------------------------------------------

    def provision_tenant(
        self,
        tenant_id: str,
        name: str,
        allowed_ips: List[str],
        key_name: str = "Default Forwarder Key",
        token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the complete per-tenant provisioning flow from the integration guide:

        1. Create tenant
        2. Add IP ranges to allowlist
        3. Create API key

        Returns: {"tenant": ..., "ips": [...], "api_key": ...}

        Store the returned api_key["api_key"] value immediately — it will
        not be retrievable after this call.
        """
        logger.info(f"Provisioning tenant '{tenant_id}'...")

        # 1. Create tenant
        tenant = self.create_tenant(tenant_id, name, token=token)
        logger.info(f"Tenant created: {tenant.get('tenant_id')}")

        # 2. Add IPs
        ip_results = []
        for ip_range in allowed_ips:
            result = self.add_ip(tenant_id, ip_range, token=token)
            ip_results.append(result)
            logger.info(f"Added IP {ip_range} to tenant '{tenant_id}'")

        # 3. Create API key
        api_key = self.create_api_key(tenant_id, key_name, token=token)
        logger.info(f"API key created: {api_key.get('key_prefix')} — SAVE THE FULL KEY NOW")

        return {
            "tenant": tenant,
            "ips": ip_results,
            "api_key": api_key,
        }


# ---------------------------------------------------------------------------
# Quick smoke test when run directly
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    client = Repo1AdminClient()

    print(f"Repo 1 base URL: {client.base_url}")
    print("Testing health endpoint...")
    try:
        h = client.health()
        print(f"Health: {h.get('status', 'unknown')}")
    except Exception as exc:
        print(f"Health check failed (is Repo 1 running?): {exc}")
        sys.exit(1)

    print("admin_client.py OK — Repo 1 is reachable.")
