from typing import Any, cast

import jwt
import pytest

from cashu.core.base import AuthProof, BlindedMessage, BlindedSignature, Proof
from cashu.core.errors import (
    BlindAuthAmountExceededError,
    BlindAuthFailedError,
    BlindAuthRateLimitExceededError,
    ClearAuthFailedError,
)
from cashu.core.settings import settings
from cashu.mint.auth.base import User
from cashu.mint.auth.server import AuthLedger


def _ledger() -> AuthLedger:
    ledger = cast(Any, object.__new__(AuthLedger))
    ledger.db = object()
    return cast(AuthLedger, ledger)


def _auth_token(secret: str = "secret", proof_id: str = "kid") -> str:
    proof = Proof(id=proof_id, amount=1, C="00", secret=secret)
    return AuthProof.from_proof(proof).to_base64()


def test_verify_oicd_issuer_accepts_matching_issuer():
    ledger = _ledger()
    ledger.issuer = "https://issuer.test"
    token = jwt.encode({"iss": "https://issuer.test"}, "secret", algorithm="HS256")

    ledger._verify_oicd_issuer(token)


def test_verify_oicd_issuer_rejects_wrong_issuer():
    ledger = _ledger()
    ledger.issuer = "https://issuer.test"
    token = jwt.encode({"iss": "https://other.test"}, "secret", algorithm="HS256")

    with pytest.raises(Exception, match="Invalid issuer"):
        ledger._verify_oicd_issuer(token)


@pytest.mark.asyncio
async def test_get_user_returns_existing_user():
    ledger = _ledger()
    existing_user = User(id="alice")

    class Crud:
        async def get_user(self, user_id, db):
            assert user_id == "alice"
            assert db is ledger.db
            return existing_user

        async def create_user(self, user, db):
            raise AssertionError("create_user should not be called")

    cast(Any, ledger).auth_crud = Crud()
    user = await ledger._get_user({"sub": "alice"})
    assert user is existing_user


@pytest.mark.asyncio
async def test_get_user_creates_missing_user():
    ledger = _ledger()
    created: dict[str, User | None] = {"user": None}

    class Crud:
        async def get_user(self, user_id, db):
            return None

        async def create_user(self, user, db):
            created["user"] = user

    cast(Any, ledger).auth_crud = Crud()
    user = await ledger._get_user({"sub": "bob"})
    assert user.id == "bob"
    assert created["user"] is not None
    assert created["user"].id == "bob"


@pytest.mark.asyncio
async def test_verify_clear_auth_maps_verification_errors(monkeypatch):
    ledger = _ledger()

    def bad_issuer(token):
        raise ValueError("bad issuer")

    monkeypatch.setattr(ledger, "_verify_oicd_issuer", bad_issuer)
    monkeypatch.setattr(ledger, "_verify_decode_jwt", lambda token: {"sub": "alice"})

    async def get_user(decoded):
        return User(id="alice")

    monkeypatch.setattr(ledger, "_get_user", get_user)

    with pytest.raises(ClearAuthFailedError):
        await ledger.verify_clear_auth("token")


@pytest.mark.asyncio
async def test_verify_clear_auth_maps_rate_limit_errors(monkeypatch):
    ledger = _ledger()
    monkeypatch.setattr(ledger, "_verify_oicd_issuer", lambda token: None)
    monkeypatch.setattr(ledger, "_verify_decode_jwt", lambda token: {"sub": "alice"})

    async def get_user(decoded):
        return User(id="alice")

    monkeypatch.setattr(ledger, "_get_user", get_user)

    def fail_limit(identifier, *args, **kwargs):
        raise Exception("too many requests")

    monkeypatch.setattr("cashu.mint.auth.server.assert_limit", fail_limit)

    with pytest.raises(BlindAuthRateLimitExceededError):
        await ledger.verify_clear_auth("token")


@pytest.mark.asyncio
async def test_verify_clear_auth_returns_user_on_success(monkeypatch):
    ledger = _ledger()
    monkeypatch.setattr(ledger, "_verify_oicd_issuer", lambda token: None)
    monkeypatch.setattr(ledger, "_verify_decode_jwt", lambda token: {"sub": "alice"})
    expected_user = User(id="alice")

    async def get_user(decoded):
        return expected_user

    monkeypatch.setattr(ledger, "_get_user", get_user)
    monkeypatch.setattr(
        "cashu.mint.auth.server.assert_limit", lambda identifier, *args, **kwargs: None
    )

    user = await ledger.verify_clear_auth("token")
    assert user is expected_user


@pytest.mark.asyncio
async def test_mint_blind_auth_enforces_maximum_outputs(monkeypatch):
    ledger = _ledger()
    monkeypatch.setattr(settings, "mint_auth_max_blind_tokens", 2)
    outputs = [BlindedMessage(id="kid", amount=1, B_=f"b{i}") for i in range(3)]

    with pytest.raises(BlindAuthAmountExceededError, match="Too many outputs"):
        await ledger.mint_blind_auth(outputs=outputs, user=User(id="alice"))


@pytest.mark.asyncio
async def test_mint_blind_auth_updates_user_and_returns_promises(monkeypatch):
    ledger = _ledger()
    monkeypatch.setattr(settings, "mint_auth_max_blind_tokens", 5)
    outputs = [BlindedMessage(id="kid", amount=1, B_="b1")]
    updated = {"user_id": None}
    signature = BlindedSignature(id="kid", amount=1, C_="aa")

    async def verify_outputs(arg):
        assert arg == outputs

    async def store_blinded(outputs_arg):
        assert outputs_arg == outputs

    async def sign_blinded(outputs_arg):
        assert outputs_arg == outputs
        return [signature]

    class Crud:
        async def update_user(self, user_id, db):
            updated["user_id"] = user_id
            assert db is ledger.db

    cast(Any, ledger)._verify_outputs = verify_outputs
    cast(Any, ledger)._store_blinded_messages = store_blinded
    cast(Any, ledger)._sign_blinded_messages = sign_blinded
    cast(Any, ledger).auth_crud = Crud()

    promises = await ledger.mint_blind_auth(outputs=outputs, user=User(id="alice"))
    assert promises == [signature]
    assert updated["user_id"] == "alice"


@pytest.mark.asyncio
async def test_verify_blind_auth_invalidates_on_success_and_unsets_pending():
    ledger = _ledger()
    token = _auth_token()
    calls = {"verified": None, "pending": None, "invalidated": None, "unset": None}

    async def verify_inputs_and_outputs(*, proofs):
        calls["verified"] = proofs[0].secret

    class DbWrite:
        async def _verify_spent_proofs_and_set_pending(self, proofs, keysets):
            calls["pending"] = proofs[0].secret

        async def _unset_proofs_pending(self, proofs, keysets):
            calls["unset"] = proofs[0].secret

        async def invalidate_proofs(self, *, proofs, keysets):
            calls["invalidated"] = proofs[0].secret

    cast(Any, ledger).verify_inputs_and_outputs = verify_inputs_and_outputs
    cast(Any, ledger).db_write = DbWrite()
    cast(Any, ledger).keysets = {"kid": object()}

    async with ledger.verify_blind_auth(token):
        pass

    assert calls == {
        "verified": "secret",
        "pending": "secret",
        "invalidated": "secret",
        "unset": "secret",
    }


@pytest.mark.asyncio
async def test_verify_blind_auth_wraps_inner_failure_and_still_unsets_pending():
    ledger = _ledger()
    token = _auth_token(secret="inner")
    calls = {"invalidated": False, "unset": False}

    async def verify_inputs_and_outputs(*, proofs):
        return None

    class DbWrite:
        async def _verify_spent_proofs_and_set_pending(self, proofs, keysets):
            return None

        async def _unset_proofs_pending(self, proofs, keysets):
            calls["unset"] = True

        async def invalidate_proofs(self, *, proofs, keysets):
            calls["invalidated"] = True

    cast(Any, ledger).verify_inputs_and_outputs = verify_inputs_and_outputs
    cast(Any, ledger).db_write = DbWrite()
    cast(Any, ledger).keysets = {"kid": object()}

    with pytest.raises(BlindAuthFailedError):
        async with ledger.verify_blind_auth(token):
            raise RuntimeError("boom")

    assert calls["invalidated"] is False
    assert calls["unset"] is True


def test_verify_decode_jwt_success(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from cashu.core.settings import settings

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    ledger = _ledger()
    ledger.issuer = "https://issuer.test"

    class MockJWKSClient:
        def get_signing_key_from_jwt(self, token):
            class MockSigningKey:
                def __init__(self, key):
                    self.key = key

            return MockSigningKey(public_key)

    ledger.jwks_client = cast(Any, MockJWKSClient())

    # Token with matching audience and matching azp
    token = jwt.encode(
        {
            "iss": "https://issuer.test",
            "aud": settings.mint_auth_oicd_client_id,
            "azp": settings.mint_auth_oicd_client_id,
            "sub": "alice",
        },
        private_key,
        algorithm="RS256",
    )

    decoded = ledger._verify_decode_jwt(token)
    assert decoded["sub"] == "alice"

    # Token with matching audience and no azp
    token_no_azp = jwt.encode(
        {
            "iss": "https://issuer.test",
            "aud": settings.mint_auth_oicd_client_id,
            "sub": "bob",
        },
        private_key,
        algorithm="RS256",
    )
    decoded_no_azp = ledger._verify_decode_jwt(token_no_azp)
    assert decoded_no_azp["sub"] == "bob"


def test_verify_decode_jwt_accepts_non_client_audience(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from cashu.core.settings import settings

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    ledger = _ledger()
    ledger.issuer = "https://issuer.test"

    class MockJWKSClient:
        def get_signing_key_from_jwt(self, token):
            class MockSigningKey:
                def __init__(self, key):
                    self.key = key

            return MockSigningKey(public_key)

    ledger.jwks_client = cast(Any, MockJWKSClient())

    # NUT-21 does not require access token audience to match the OIDC client id.
    token = jwt.encode(
        {
            "iss": "https://issuer.test",
            "aud": "account",
            "azp": settings.mint_auth_oicd_client_id,
            "sub": "alice",
        },
        private_key,
        algorithm="RS256",
    )

    decoded = ledger._verify_decode_jwt(token)
    assert decoded["sub"] == "alice"


def test_verify_decode_jwt_rejects_mismatched_azp(monkeypatch):
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    from cashu.core.settings import settings

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    ledger = _ledger()
    ledger.issuer = "https://issuer.test"

    class MockJWKSClient:
        def get_signing_key_from_jwt(self, token):
            class MockSigningKey:
                def __init__(self, key):
                    self.key = key

            return MockSigningKey(public_key)

    ledger.jwks_client = cast(Any, MockJWKSClient())

    # Token with matching audience but mismatched azp
    token = jwt.encode(
        {
            "iss": "https://issuer.test",
            "aud": settings.mint_auth_oicd_client_id,
            "azp": "wrong-client",
            "sub": "alice",
        },
        private_key,
        algorithm="RS256",
    )

    with pytest.raises(jwt.InvalidTokenError, match="does not match mint client"):
        ledger._verify_decode_jwt(token)


@pytest.mark.asyncio
async def test_verify_clear_auth_uses_correct_rate_limit(monkeypatch):
    ledger = _ledger()
    monkeypatch.setattr(ledger, "_verify_oicd_issuer", lambda token: None)
    monkeypatch.setattr(ledger, "_verify_decode_jwt", lambda token: {"sub": "alice"})

    async def get_user(decoded):
        return User(id="alice")

    monkeypatch.setattr(ledger, "_get_user", get_user)

    captured_limit = []

    def mock_assert_limit(identifier, limit=None):
        captured_limit.append(limit)

    monkeypatch.setattr("cashu.mint.auth.server.assert_limit", mock_assert_limit)
    monkeypatch.setattr(settings, "mint_auth_rate_limit_per_minute", 42)

    await ledger.verify_clear_auth("token")
    assert len(captured_limit) == 1
    assert captured_limit[0] == 42
