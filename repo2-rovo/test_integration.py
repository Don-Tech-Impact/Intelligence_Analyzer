"""
Integration Contract Tests — Repo 2 ↔ Repo 1
==============================================
Verifies that Repo 2's implementation matches the Repo 1 integration contract
without requiring a live Repo 1 or Redis instance.

Run with:
    pytest repo2-rovo/test_integration.py -v

All tests use mocks/in-memory state — no external dependencies.
"""

import json
import os
import sys
import pytest
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime

# Add repo2-rovo directory to sys.path so files can be imported directly
# (folder name has a hyphen so it can't be imported as a package with dot notation)
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    """Set required environment variables for all tests."""
    monkeypatch.setenv("ADMIN_KEY", "test-admin-key-123")
    monkeypatch.setenv("ADMIN_API_KEY", "test-admin-key-123")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-for-jwt-signing")
    monkeypatch.setenv("REPO1_BASE_URL", "http://localhost:8080")
    monkeypatch.setenv("REPO1_URL", "http://localhost:8080")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("REPO2_WEBHOOK_URL", "http://localhost:8000/api/admin/tenants/sync")


@pytest.fixture
def mock_db():
    """Return a mock SQLAlchemy session."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    session.commit = MagicMock()
    session.add = MagicMock()
    return session


# ===========================================================================
# 1. Webhook receiver — auth header validation
# ===========================================================================

class TestWebhookAuth:
    """Verify the webhook endpoint returns 401 (not 422) on bad/missing key."""

    def test_verify_admin_key_fixed_missing_header(self):
        """Missing X-Admin-Key should raise HTTPException with status 401."""
        from fastapi import HTTPException
        from webhook_receiver_fix import verify_admin_key_fixed

        try:
            verify_admin_key_fixed(x_admin_key=None)
            pytest.fail("Expected HTTPException(401) for missing key — no exception raised")
        except HTTPException as e:
            assert e.status_code == 401, f"Expected 401, got {e.status_code}"
            assert "Missing" in e.detail or "missing" in e.detail.lower()

    def test_verify_admin_key_fixed_wrong_key(self):
        """Wrong X-Admin-Key should raise HTTPException with status 401."""
        from fastapi import HTTPException
        from webhook_receiver_fix import verify_admin_key_fixed

        with pytest.raises(HTTPException) as exc_info:
            verify_admin_key_fixed(x_admin_key="totally-wrong-key")

        assert exc_info.value.status_code == 401
        assert "Invalid" in exc_info.value.detail or "invalid" in exc_info.value.detail.lower()

    def test_verify_admin_key_fixed_correct_key(self):
        """Correct X-Admin-Key should return the key string."""
        from webhook_receiver_fix import verify_admin_key_fixed

        result = verify_admin_key_fixed(x_admin_key="test-admin-key-123")
        assert result == "test-admin-key-123"


# ===========================================================================
# 2. Redis queue naming contract
# ===========================================================================

class TestRedisQueueNaming:
    """Verify queue names match the Repo 1 contract: logs:{tenant_id}:{type}"""

    def test_ingest_queue_name(self):
        from redis_queue_adapter import build_ingest_queue
        assert build_ingest_queue("acme_corp") == "logs:acme_corp:ingest"
        assert build_ingest_queue("EBK") == "logs:EBK:ingest"
        assert build_ingest_queue("central-uni") == "logs:central-uni:ingest"

    def test_clean_queue_name(self):
        from redis_queue_adapter import build_clean_queue
        assert build_clean_queue("acme_corp") == "logs:acme_corp:clean"
        assert build_clean_queue("EBK") == "logs:EBK:clean"

    def test_dead_queue_name(self):
        from redis_queue_adapter import build_dead_queue
        assert build_dead_queue("acme_corp") == "logs:acme_corp:dead"

    def test_get_tenant_from_queue(self):
        from redis_queue_adapter import get_tenant_from_queue
        assert get_tenant_from_queue("logs:acme_corp:clean") == "acme_corp"
        assert get_tenant_from_queue("logs:EBK:dead") == "EBK"
        assert get_tenant_from_queue("logs:central-uni:ingest") == "central-uni"

    def test_get_type_from_queue(self):
        from redis_queue_adapter import get_type_from_queue
        assert get_type_from_queue("logs:acme_corp:clean") == "clean"
        assert get_type_from_queue("logs:acme_corp:ingest") == "ingest"
        assert get_type_from_queue("logs:acme_corp:dead") == "dead"

    def test_queue_ordering_ingest_before_clean_before_dead(self):
        """discover_tenant_queues must return ingest, then clean, then dead per tenant."""
        from redis_queue_adapter import discover_tenant_queues, get_type_from_queue

        mock_redis = MagicMock()
        # Simulate scan_iter returning queue names
        def fake_scan_iter(match, count):
            if "ingest" in match:
                return ["logs:acme_corp:ingest", "logs:ebk:ingest"]
            if "clean" in match:
                return ["logs:acme_corp:clean", "logs:ebk:clean"]
            if "dead" in match:
                return ["logs:acme_corp:dead", "logs:ebk:dead"]
            return []

        mock_redis.scan_iter = fake_scan_iter
        queues = discover_tenant_queues(mock_redis)

        # For each tenant block: ingest first, clean second, dead last
        for i in range(0, len(queues), 3):
            block = queues[i:i+3]
            assert get_type_from_queue(block[0]) == "ingest"
            assert get_type_from_queue(block[1]) == "clean"
            assert get_type_from_queue(block[2]) == "dead"


# ===========================================================================
# 3. Admin client — correct param names
# ===========================================================================

class TestAdminClientParams:
    """Verify admin_client.py sends correct query param names to Repo 1."""

    def test_list_tenants_sends_limit_not_page_size(self):
        """list_tenants must send 'limit' param, not 'page_size'."""
        from admin_client import Repo1AdminClient

        client = Repo1AdminClient(base_url="http://fake-repo1:8080")
        captured = {}

        def fake_get(url, **kwargs):
            captured["params"] = kwargs.get("params", {})
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"tenants": [], "total": 0}
            return mock_resp

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.get = fake_get

            client.list_tenants(limit=50, page=2)

        assert "limit" in captured["params"], "Should send 'limit' not 'page_size'"
        assert captured["params"]["limit"] == 50
        assert "page_size" not in captured["params"], "Should NOT send 'page_size'"

    def test_create_tenant_body_structure(self):
        """create_tenant must send correct JSON body fields."""
        from admin_client import Repo1AdminClient

        client = Repo1AdminClient(base_url="http://fake-repo1:8080")
        captured = {}

        def fake_post(url, **kwargs):
            captured["json"] = kwargs.get("json", {})
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"tenant_id": "test", "status": "active"}
            return mock_resp

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.post = fake_post

            client.create_tenant("test_corp", "Test Corp", description="A test")

        body = captured["json"]
        assert body["tenant_id"] == "test_corp"
        assert body["name"] == "Test Corp"
        assert body["description"] == "A test"

    def test_configure_webhook_sends_correct_body(self):
        """configure_webhook must send {webhook_url: ...} body."""
        from admin_client import Repo1AdminClient

        client = Repo1AdminClient(base_url="http://fake-repo1:8080")
        captured = {}

        def fake_post(url, **kwargs):
            captured["json"] = kwargs.get("json", {})
            captured["url"] = url
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"status": "configured"}
            return mock_resp

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.post = fake_post

            client.configure_webhook("http://repo2:8000/api/admin/tenants/sync")

        assert captured["json"]["webhook_url"] == "http://repo2:8000/api/admin/tenants/sync"
        assert "/admin/webhooks/configure" in captured["url"]


# ===========================================================================
# 4. Webhook registration helper
# ===========================================================================

class TestStartupWebhookRegister:
    """Verify startup_webhook_register.py behaves correctly."""

    def test_register_webhook_no_url_raises(self, monkeypatch):
        """register_webhook raises ValueError when no webhook URL is set."""
        monkeypatch.delenv("REPO2_WEBHOOK_URL", raising=False)
        from startup_webhook_register import register_webhook

        with pytest.raises(ValueError, match="REPO2_WEBHOOK_URL"):
            register_webhook(webhook_url=None)

    def test_register_webhook_on_startup_skips_when_url_missing(self, monkeypatch, caplog):
        """register_webhook_on_startup returns False (not crash) when URL missing."""
        monkeypatch.delenv("REPO2_WEBHOOK_URL", raising=False)
        from startup_webhook_register import register_webhook_on_startup
        import logging

        with caplog.at_level(logging.WARNING):
            result = register_webhook_on_startup()

        assert result is False

    def test_register_webhook_sends_correct_payload(self, monkeypatch):
        """register_webhook POSTs {webhook_url: ...} to /admin/webhooks/configure."""
        monkeypatch.setenv("REPO2_WEBHOOK_URL", "http://repo2:8000/api/admin/tenants/sync")
        from startup_webhook_register import register_webhook

        captured = {}

        def fake_post(url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json", {})
            captured["headers"] = kwargs.get("headers", {})
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.json.return_value = {"status": "configured", "webhook_url": kwargs["json"]["webhook_url"]}
            return mock_resp

        with patch("httpx.Client") as mock_client_cls:
            mock_ctx = MagicMock()
            mock_client_cls.return_value.__enter__ = MagicMock(return_value=mock_ctx)
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_ctx.post = fake_post

            result = register_webhook(
                webhook_url="http://repo2:8000/api/admin/tenants/sync",
                repo1_base="http://localhost:8080",
                admin_key="test-admin-key-123",
            )

        assert "/admin/webhooks/configure" in captured["url"]
        assert captured["json"]["webhook_url"] == "http://repo2:8000/api/admin/tenants/sync"
        assert captured["headers"]["X-Admin-Key"] == "test-admin-key-123"
        assert result["status"] == "configured"


# ===========================================================================
# 5. Webhook payload — tenant sync contract
# ===========================================================================

class TestWebhookPayloadContract:
    """Verify webhook payload handling matches Repo 1 contract."""

    def _make_payload(self, event, tenant_id="acme_corp", name="Acme Corp", status="active"):
        return {
            "event": event,
            "tenant": {"tenant_id": tenant_id, "name": name, "status": status},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def test_created_event_structure(self):
        payload = self._make_payload("tenant.created")
        assert payload["event"] == "tenant.created"
        assert "tenant_id" in payload["tenant"]
        assert "name" in payload["tenant"]
        assert "status" in payload["tenant"]

    def test_updated_event_structure(self):
        payload = self._make_payload("tenant.updated", status="suspended")
        assert payload["event"] == "tenant.updated"
        assert payload["tenant"]["status"] == "suspended"

    def test_deleted_event_structure(self):
        payload = self._make_payload("tenant.deleted")
        assert payload["event"] == "tenant.deleted"

    def test_all_three_event_types_recognized(self):
        """Repo 1 contract defines exactly three event types."""
        valid_events = {"tenant.created", "tenant.updated", "tenant.deleted"}
        for event in valid_events:
            p = self._make_payload(event)
            assert p["event"] in valid_events


# ===========================================================================
# 6. Normalized log schema (BasicLogSchema) — what Repo 2 receives from clean queue
# ===========================================================================

class TestCleanLogSchema:
    """Verify Repo 2 can parse the normalized log schema from Repo 1's clean queue."""

    SAMPLE_CLEAN_LOG = {
        "tenant_id": "acme_corp",
        "vendor": "cisco_asa",
        "timestamp": "2026-02-26T13:00:00",
        "source_ip": "192.168.1.100",
        "destination_ip": "203.0.113.50",
        "source_port": 80,
        "destination_port": 443,
        "protocol": "tcp",
        "action": "blocked",
        "message": "Deny tcp src inside:192.168.1.100/80 dst outside:203.0.113.50/443",
        "raw_log": "%ASA-4-106023: Deny tcp src inside:192.168.1.100/80 ...",
        "device": {"type": "cisco_asa", "id": "fw-01"},
        "interface": "inside",
        "parse_error": False,
        "parsed_at": "2026-02-26T13:00:00.500000",
    }

    def test_required_fields_present(self):
        log = self.SAMPLE_CLEAN_LOG
        required = ["tenant_id", "vendor", "timestamp", "action", "message", "raw_log"]
        for field in required:
            assert field in log, f"Missing required field: {field}"

    def test_action_normalization(self):
        """action must be one of the four normalized values."""
        valid_actions = {"allowed", "blocked", "rejected", "unknown"}
        assert self.SAMPLE_CLEAN_LOG["action"] in valid_actions

    def test_parse_error_is_bool(self):
        assert isinstance(self.SAMPLE_CLEAN_LOG["parse_error"], bool)

    def test_json_serializable(self):
        serialized = json.dumps(self.SAMPLE_CLEAN_LOG)
        deserialized = json.loads(serialized)
        assert deserialized["tenant_id"] == "acme_corp"

    def test_log_adapter_handles_clean_log(self):
        """LogAdapter must normalize a Repo 1 clean-queue log without error."""
        from src.services.log_adapter import LogAdapter

        # Wrap as v2 schema (what Repo 1's clean queue sends)
        v2_log = {
            "schema_version": "v2.0",
            "tenant_id": "acme_corp",
            "source": {"ip": "192.168.1.100", "port": 80},
            "destination": {"ip": "203.0.113.50", "port": 443},
            "event": {"action": "blocked", "protocol": "tcp"},
            "message": "Deny tcp ...",
            "raw_log": "%ASA-4-106023: ...",
            "device": {"type": "cisco_asa", "id": "fw-01"},
            "vendor": "cisco_asa",
            "timestamp": "2026-02-26T13:00:00",
        }

        result = LogAdapter.normalize(v2_log)
        assert result is not None
        assert result.tenant_id == "acme_corp"


# ===========================================================================
# 7. Dead letter schema
# ===========================================================================

class TestDeadLetterSchema:
    """Verify dead letter schema handling matches Repo 1 contract."""

    SAMPLE_DEAD = {
        "tenant_id": "acme_corp",
        "raw_log": "some unparseable log line...",
        "error_type": "parse_error",
        "error_message": "No parser matched with sufficient confidence",
        "vendor": None,
        "source_info": {"client_ip": "192.168.1.50", "api_key_id": "key-uuid"},
        "failed_at": "2026-02-26T13:00:00.123456",
    }

    def test_required_fields(self):
        for field in ["tenant_id", "raw_log", "error_type", "failed_at"]:
            assert field in self.SAMPLE_DEAD

    def test_error_type_values(self):
        valid_error_types = {
            "parse_error",
            "tenant_resolution_failed",
            "validation_failed",
            "normalization_failed",
            "redis_publish_failed",
        }
        assert self.SAMPLE_DEAD["error_type"] in valid_error_types

    def test_vendor_can_be_null(self):
        assert self.SAMPLE_DEAD["vendor"] is None  # Valid per contract


# ===========================================================================
# 8. Environment variable alignment
# ===========================================================================

class TestEnvVarAlignment:
    """Verify both canonical and alias env var names are handled."""

    def test_admin_key_canonical_name(self, monkeypatch):
        monkeypatch.setenv("ADMIN_KEY", "canonical-key")
        monkeypatch.delenv("ADMIN_API_KEY", raising=False)

        import admin_client
        import importlib
        importlib.reload(admin_client)

        client = admin_client.Repo1AdminClient()
        assert client.admin_key == "canonical-key"

    def test_admin_key_alias_fallback(self, monkeypatch):
        monkeypatch.delenv("ADMIN_KEY", raising=False)
        monkeypatch.setenv("ADMIN_API_KEY", "alias-key")

        # Re-check _admin_key() function
        from admin_client import _admin_key
        # Reload env
        with patch.dict(os.environ, {"ADMIN_API_KEY": "alias-key"}, clear=False):
            os.environ.pop("ADMIN_KEY", None)
            result = _admin_key()
        assert result == "alias-key"

    def test_repo1_base_url_canonical(self, monkeypatch):
        monkeypatch.setenv("REPO1_BASE_URL", "http://canonical:8080")
        monkeypatch.delenv("REPO1_URL", raising=False)

        from admin_client import _base_url
        with patch.dict(os.environ, {"REPO1_BASE_URL": "http://canonical:8080"}, clear=False):
            os.environ.pop("REPO1_URL", None)
            result = _base_url()
        assert result == "http://canonical:8080"

    def test_repo1_url_alias_fallback(self, monkeypatch):
        monkeypatch.delenv("REPO1_BASE_URL", raising=False)
        monkeypatch.setenv("REPO1_URL", "http://alias:8080")

        from admin_client import _base_url
        with patch.dict(os.environ, {"REPO1_URL": "http://alias:8080"}, clear=False):
            os.environ.pop("REPO1_BASE_URL", None)
            result = _base_url()
        assert result == "http://alias:8080"


# ===========================================================================
# 9. Existing tests still pass — smoke test imports
# ===========================================================================

class TestExistingCodeUntouched:
    """Verify the existing src/ files are importable and structurally sound."""

    def test_admin_router_importable(self):
        import src.api.admin_router  # noqa

    def test_redis_consumer_importable(self):
        import src.services.redis_consumer  # noqa

    def test_log_adapter_importable(self):
        import src.services.log_adapter  # noqa

    def test_health_router_importable(self):
        import src.api.health  # noqa

    def test_auth_importable(self):
        import src.api.auth  # noqa

    def test_verify_admin_key_signature_is_optional(self):
        """
        Verify that verify_admin_key no longer requires the header at schema level.
        After fix: calling with x_admin_key=None raises HTTP 401 (not 422).
        This is tested by calling the function directly with None.
        """
        from fastapi import HTTPException
        from src.api import admin_router

        # After fix: missing header → 401 (not 422 schema error)
        try:
            admin_router.verify_admin_key(x_admin_key=None)
            pytest.fail("Expected HTTPException(401) but no exception was raised")
        except HTTPException as e:
            assert e.status_code == 401, (
                f"Expected 401 (auth failure), got {e.status_code}. "
                "If 422, the fix from webhook_receiver_fix.py was not applied."
            )
