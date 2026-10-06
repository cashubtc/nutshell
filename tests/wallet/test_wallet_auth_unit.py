import jwt
import pytest

from cashu.core.base import AuthProof, WalletKeyset
from cashu.core.crypto.secp import PrivateKey
from cashu.core.db import Database
from cashu.core.errors import BlindAuthFailedError
from cashu.core.migrations import migrate_databases
from cashu.core.mint_info import MintInfo
from cashu.core.settings import settings
from cashu.mint.auth import migrations as auth_migrations
from cashu.mint.auth.base import User
from cashu.mint.auth.crud import AuthLedgerCrudSqlite
from cashu.mint.auth.server import AuthLedger
from cashu.wallet.auth.auth import WalletAuth
from cashu.wallet.auth.openid_connect.openid_client import (
    AuthorizationFlow,
    OpenIDClient,
)
from cashu.wallet.crud import get_proofs


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version, keyset_prefix",
    [
        ("0.19.0", "00"),
        ("0.20.0", "01"),
        ("0.21.0", "01"),
        ("0.21.99", "01"),
        ("0.22.0", "02"),
    ],
)
async def test_auth_tokens_mint_and_spend_across_keyset_versions(
    monkeypatch, tmp_path, version, keyset_prefix
):
    monkeypatch.setattr(settings, "version", version)
    db = Database("auth", str(tmp_path / "mint"))
    ledger = AuthLedger(
        db=db,
        seed="TEST_AUTH_SEED",
        amounts=[1],
        derivation_path="m/0'/999'/0'",
    )
    wallet = await WalletAuth.with_db(
        url="https://mint.test", db=str(tmp_path / "wallet")
    )
    try:
        await migrate_databases(db, auth_migrations)
        await ledger.init_keysets()
        assert ledger.keyset.id.startswith(keyset_prefix)
        assert ledger.keyset.public_keys
        ledger.auth_crud = AuthLedgerCrudSqlite()
        user = User(id="alice")
        await ledger.auth_crud.create_user(db=db, user=user)

        # An upgraded wallet must still mint tokens with older auth keysets.
        monkeypatch.setattr(settings, "version", "0.22.0")
        wallet.keyset_id = ledger.keyset.id
        wallet.keysets = {
            ledger.keyset.id: WalletKeyset(
                id=ledger.keyset.id,
                unit="auth",
                public_keys=ledger.keyset.public_keys,
            )
        }
        wallet.mint_info = MintInfo.model_construct(nuts={22: {"bat_max_mint": 2}})
        token = jwt.encode({"sub": "alice"}, "a" * 32, algorithm="HS256")
        wallet.oidc_client = OpenIDClient(
            discovery_url="https://issuer.test/.well-known/openid-configuration",
            client_id="cashu-client",
            auth_flow=AuthorizationFlow.PASSWORD,
            access_token=token,
        )

        async def mint_tokens(clear_auth_token, outputs):
            assert clear_auth_token == token
            return await ledger.mint_blind_auth(outputs=outputs, user=user)

        monkeypatch.setattr(wallet, "blind_mint_blind_auth", mint_tokens)
        proofs = await wallet.mint_blind_auth()
        assert len(proofs) == 2
        assert len({proof.secret for proof in proofs}) == 2
        assert len(await get_proofs(db=wallet.db)) == 2

        for proof in proofs:
            tampered = proof.model_copy(
                update={"secret": PrivateKey().public_key.format().hex()}
            )
            with pytest.raises(BlindAuthFailedError):
                async with ledger.verify_blind_auth(
                    AuthProof.from_proof(tampered).to_base64()
                ):
                    pass
            auth_token = AuthProof.from_proof(proof).to_base64()
            async with ledger.verify_blind_auth(auth_token):
                pass
            with pytest.raises(BlindAuthFailedError):
                async with ledger.verify_blind_auth(auth_token):
                    pass
    finally:
        await wallet.db.engine.dispose()
        await db.engine.dispose()
