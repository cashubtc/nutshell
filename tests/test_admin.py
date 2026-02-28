"""Tests for the Nutshell Admin UI."""

import base64
from unittest.mock import MagicMock

import grpc
import pytest
from fastapi.testclient import TestClient

from cashu.mint.admin.app import (
    VALID_MELT_QUOTE_STATES,
    VALID_MINT_QUOTE_STATES,
    AdminUI,
    _format_timestamp,
    create_admin_app,
)


class MockAdminUI(AdminUI):
    """AdminUI subclass that doesn't connect to a real gRPC server."""

    def __init__(self):
        # Skip parent __init__ — no real gRPC connection
        self.mint_url = "http://localhost:3338"
        self.grpc_host = "localhost"
        self.grpc_port = 8086
        self._stub = MagicMock()
        self._channel = MagicMock()

    def get_info(self) -> dict:
        return {
            "name": "Test Mint",
            "version": "0.18.2",
            "description": "A test mint",
            "long_description": "Long description",
            "motd": "Welcome",
            "icon_url": "",
            "urls": ["https://mint.example.com"],
            "contact": [{"method": "email", "info": "test@example.com"}],
            "pubkey": "02abcdef1234567890",
            "tos_url": "",
            "connected": True,
        }

    async def get_mint_info_rest(self) -> dict:
        return {"name": "Test Mint", "version": "0.18.2"}

    async def get_keysets_rest(self) -> dict:
        return {
            "keysets": [
                {"id": "00abc123", "unit": "sat", "active": True, "input_fee_ppk": 0},
                {"id": "00def456", "unit": "sat", "active": False, "input_fee_ppk": 100},
            ]
        }

    def update_name(self, name: str) -> str:
        return "Name updated"

    def update_motd(self, motd: str) -> str:
        return "MOTD updated"

    def update_description(self, desc: str) -> str:
        return "Description updated"

    def update_long_description(self, desc: str) -> str:
        return "Long description updated"

    def update_icon_url(self, url: str) -> str:
        return "Icon URL updated"

    def update_lightning_fee(self, fee_percent=None, fee_min_reserve=None) -> str:
        return "Lightning fee updated"

    def update_quote_ttl(self, mint_ttl=None, melt_ttl=None) -> str:
        return "Quote TTL updated"

    def rotate_keyset(self, unit: str, input_fee_ppk=None) -> dict:
        return {"id": "00new789", "unit": unit, "max_order": 64, "input_fee_ppk": input_fee_ppk or 0}

    def get_mint_quote(self, quote_id: str) -> dict:
        return {
            "quote": quote_id,
            "method": "bolt11",
            "unit": "sat",
            "amount": 1000,
            "state": "PAID",
            "created_time": 1700000000,
            "paid_time": 1700001000,
            "expiry": 1700100000,
        }

    def get_melt_quote(self, quote_id: str) -> dict:
        return {
            "quote": quote_id,
            "method": "bolt11",
            "unit": "sat",
            "amount": 500,
            "fee_reserve": 10,
            "state": "PENDING",
            "fee_paid": 0,
            "payment_preimage": "",
            "created_time": 1700000000,
            "paid_time": 0,
            "expiry": 1700100000,
        }

    def update_mint_quote_state(self, quote_id: str, state: str) -> str:
        return f"Mint quote {quote_id} → {state}"

    def update_melt_quote_state(self, quote_id: str, state: str) -> str:
        return f"Melt quote {quote_id} → {state}"

    def add_url(self, url: str) -> str:
        return f"URL added: {url}"

    def remove_url(self, url: str) -> str:
        return f"URL removed: {url}"

    def add_contact(self, method: str, info: str) -> str:
        return f"Contact added: {method}"

    def remove_contact(self, method: str) -> str:
        return f"Contact removed: {method}"


@pytest.fixture
def mock_admin():
    return MockAdminUI()


@pytest.fixture
def client(mock_admin):
    app = create_admin_app(mock_admin)
    return TestClient(app)


@pytest.fixture
def auth_client(mock_admin):
    app = create_admin_app(mock_admin, admin_password="testpass123")
    return TestClient(app)


def _basic_auth_header(user: str, password: str) -> dict:
    creds = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


# --- Authentication tests ---


class TestAuth:
    def test_no_auth_allows_access(self, client):
        """Without admin_password set, all requests pass through."""
        resp = client.get("/")
        assert resp.status_code == 200

    def test_auth_returns_401_without_credentials(self, auth_client):
        """With admin_password set, requests without credentials get 401."""
        resp = auth_client.get("/", follow_redirects=False)
        assert resp.status_code == 401
        assert "WWW-Authenticate" in resp.headers

    def test_auth_correct_password(self, auth_client):
        """Correct credentials grant access."""
        resp = auth_client.get("/", headers=_basic_auth_header("admin", "testpass123"))
        assert resp.status_code == 200

    def test_auth_wrong_password(self, auth_client):
        """Wrong password gets 401."""
        resp = auth_client.get("/", headers=_basic_auth_header("admin", "wrongpass"))
        assert resp.status_code == 401

    def test_auth_wrong_username(self, auth_client):
        """Wrong username gets 401."""
        resp = auth_client.get("/", headers=_basic_auth_header("notadmin", "testpass123"))
        assert resp.status_code == 401

    def test_auth_malformed_header(self, auth_client):
        """Malformed auth header gets 401."""
        resp = auth_client.get("/", headers={"Authorization": "Basic notbase64!!!"})
        assert resp.status_code == 401


# --- Page rendering tests ---


class TestPages:
    def test_dashboard(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text
        assert "Test Mint" in resp.text

    def test_settings(self, client):
        resp = client.get("/settings")
        assert resp.status_code == 200
        assert "Settings" in resp.text
        assert "Mint Identity" in resp.text

    def test_keysets(self, client):
        resp = client.get("/keysets")
        assert resp.status_code == 200
        assert "Keysets" in resp.text
        assert "00abc123" in resp.text

    def test_quotes(self, client):
        resp = client.get("/quotes")
        assert resp.status_code == 200
        assert "Quotes" in resp.text
        assert "Look Up Quote" in resp.text

    def test_monitoring(self, client):
        resp = client.get("/monitoring")
        assert resp.status_code == 200
        assert "Monitoring" in resp.text
        assert "System Information" in resp.text

    def test_favicon(self, client):
        resp = client.get("/favicon.ico")
        assert resp.status_code == 204


# --- Quote state validation tests ---


class TestQuoteValidation:
    def test_valid_mint_quote_states(self, client):
        for state in VALID_MINT_QUOTE_STATES:
            resp = client.post(
                "/quotes/update-state",
                data={"quote_type": "mint", "quote_id": "test123", "state": state},
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert "Operation+failed" not in resp.headers["location"]

    def test_valid_melt_quote_states(self, client):
        for state in VALID_MELT_QUOTE_STATES:
            resp = client.post(
                "/quotes/update-state",
                data={"quote_type": "melt", "quote_id": "test123", "state": state},
                follow_redirects=False,
            )
            assert resp.status_code == 303
            assert "Operation+failed" not in resp.headers["location"]

    def test_invalid_mint_state_rejected(self, client):
        resp = client.post(
            "/quotes/update-state",
            data={"quote_type": "mint", "quote_id": "test123", "state": "BOGUS"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+quote+state" in resp.headers["location"]

    def test_invalid_melt_state_issued_rejected(self, client):
        """ISSUED is valid for mint but not melt."""
        resp = client.post(
            "/quotes/update-state",
            data={"quote_type": "melt", "quote_id": "test123", "state": "ISSUED"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+quote+state" in resp.headers["location"]


# --- Error sanitization tests ---


class TestErrorSanitization:
    def _make_grpc_error_admin(self):
        """Create an admin whose update_name raises a gRPC error with details."""
        admin = MockAdminUI()

        def raise_grpc_error(name):
            error = grpc.RpcError()
            error.details = lambda: "internal: secret database connection string"
            error.code = lambda: grpc.StatusCode.INTERNAL
            raise error

        admin.update_name = raise_grpc_error
        return admin

    def test_grpc_error_details_not_leaked(self):
        admin = self._make_grpc_error_admin()
        app = create_admin_app(admin)
        client = TestClient(app)
        resp = client.post(
            "/settings/name",
            data={"name": "test"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        location = resp.headers["location"]
        assert "secret" not in location
        assert "database" not in location
        assert "Operation+failed" in location


# --- API endpoint tests ---


class TestAPI:
    def test_api_system(self, client):
        resp = client.get("/api/system")
        assert resp.status_code == 200
        data = resp.json()
        assert "platform" in data
        assert "python" in data

    def test_api_info(self, client):
        resp = client.get("/api/info")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Test Mint"
        assert data["connected"] is True


# --- Settings POST tests ---


class TestSettingsPosts:
    def test_update_name(self, client):
        resp = client.post("/settings/name", data={"name": "New Name"}, follow_redirects=False)
        assert resp.status_code == 303
        assert "Name+updated" in resp.headers["location"]

    def test_update_motd(self, client):
        resp = client.post("/settings/motd", data={"motd": "Hello"}, follow_redirects=False)
        assert resp.status_code == 303
        assert "MOTD+updated" in resp.headers["location"]

    def test_update_description(self, client):
        resp = client.post("/settings/description", data={"description": "Desc"}, follow_redirects=False)
        assert resp.status_code == 303
        assert "Description+updated" in resp.headers["location"]

    def test_update_lightning_fee(self, client):
        resp = client.post(
            "/settings/lightning-fee",
            data={"fee_percent": "1.5", "fee_min_reserve": "2000"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Lightning+fee+updated" in resp.headers["location"]

    def test_rotate_keyset(self, client):
        resp = client.post(
            "/keysets/rotate",
            data={"unit": "sat", "input_fee_ppk": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Rotated" in resp.headers["location"]

    def test_lookup_mint_quote(self, client):
        resp = client.post(
            "/quotes/lookup",
            data={"quote_type": "mint", "quote_id": "testquote1"},
        )
        assert resp.status_code == 200
        assert "testquote1" in resp.text
        assert "PAID" in resp.text

    def test_lookup_melt_quote(self, client):
        resp = client.post(
            "/quotes/lookup",
            data={"quote_type": "melt", "quote_id": "testquote2"},
        )
        assert resp.status_code == 200
        assert "testquote2" in resp.text
        assert "PENDING" in resp.text


# --- Timestamp filter tests ---


class TestTimestampFilter:
    def test_format_valid_timestamp(self):
        result = _format_timestamp(1700000000)
        assert "2023-11-14" in result
        assert "UTC" in result

    def test_format_zero(self):
        assert _format_timestamp(0) == "—"

    def test_format_none(self):
        assert _format_timestamp(None) == "—"

    def test_format_empty_string(self):
        assert _format_timestamp("") == "—"

    def test_format_invalid(self):
        assert _format_timestamp("not-a-timestamp") == "not-a-timestamp"


# --- Security header tests ---


class TestSecurityHeaders:
    def test_x_frame_options(self, client):
        resp = client.get("/")
        assert resp.headers["X-Frame-Options"] == "DENY"

    def test_x_content_type_options(self, client):
        resp = client.get("/")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"

    def test_csp_frame_ancestors(self, client):
        resp = client.get("/")
        assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]


# --- ValueError handling tests ---


class TestNumericInputValidation:
    def test_invalid_fee_percent(self, client):
        resp = client.post(
            "/settings/lightning-fee",
            data={"fee_percent": "abc", "fee_min_reserve": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+numeric+input" in resp.headers["location"]

    def test_invalid_fee_min_reserve(self, client):
        resp = client.post(
            "/settings/lightning-fee",
            data={"fee_percent": "", "fee_min_reserve": "xyz"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+numeric+input" in resp.headers["location"]

    def test_invalid_mint_ttl(self, client):
        resp = client.post(
            "/settings/quote-ttl",
            data={"mint_ttl": "not_a_number", "melt_ttl": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+numeric+input" in resp.headers["location"]

    def test_invalid_input_fee_ppk(self, client):
        resp = client.post(
            "/keysets/rotate",
            data={"unit": "sat", "input_fee_ppk": "bad"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+numeric+input" in resp.headers["location"]


# --- quote_type validation tests ---


class TestQuoteTypeValidation:
    def test_invalid_quote_type_lookup(self, client):
        resp = client.post(
            "/quotes/lookup",
            data={"quote_type": "bogus", "quote_id": "test123"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+quote+type" in resp.headers["location"]

    def test_invalid_quote_type_update_state(self, client):
        resp = client.post(
            "/quotes/update-state",
            data={"quote_type": "bogus", "quote_id": "test123", "state": "PAID"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "Invalid+quote+type" in resp.headers["location"]
