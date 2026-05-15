import time

import pytest
import pytest_asyncio

from cashu.core.base import (
    BlindedSignature,
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    Proof,
    WalletKeyset,
    WalletMint,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations as wallet_migrations
from cashu.wallet.crud import (
    bump_secret_derivation,
    delete_keyset,
    get_bolt11_melt_quote,
    get_bolt11_melt_quotes,
    get_bolt11_mint_quote,
    get_bolt11_mint_quotes,
    get_keysets,
    get_mint_by_url,
    get_proofs,
    get_reserved_proofs,
    get_seed_and_mnemonic,
    invalidate_proof,
    secret_used,
    set_secret_derivation,
    store_bolt11_melt_quote,
    store_bolt11_mint_quote,
    store_keyset,
    store_mint,
    store_proof,
    store_seed_and_mnemonic,
    update_bolt11_melt_quote,
    update_bolt11_mint_quote,
    update_keyset,
    update_mint,
    update_proof,
)


@pytest_asyncio.fixture
async def wallet_db(tmp_path):
    db = Database("wallet", str(tmp_path))
    await migrate_databases(db, wallet_migrations)
    yield db
    await db.engine.dispose()


def _proof(
    secret: str,
    *,
    id: str = "keyset-id",
    mint_id: str | None = None,
    melt_id: str | None = None,
):
    return Proof(
        id=id,
        amount=1,
        C=PrivateKey().public_key.format().hex(),
        secret=secret,
        mint_id=mint_id,
        melt_id=melt_id,
    )


def _keyset(keyset_id: str = "keyset-1"):
    return WalletKeyset(
        id=keyset_id,
        unit="sat",
        public_keys={1: PrivateKey().public_key},
        mint_url="https://mint.test",
        active=True,
        input_fee_ppk=1,
    )


def _mint_quote(quote: str, state: MintQuoteState):
    return MintQuote(
        quote=quote,
        method="bolt11",
        request=f"req-{quote}",
        checking_id=f"chk-{quote}",
        unit="sat",
        amount=21,
        state=state,
        mint="https://mint.test",
        created_time=int(time.time()),
        expiry=int(time.time()) + 1000,
        paid_time=None,
        privkey="",
    )


def _melt_quote(quote: str, state: MeltQuoteState):
    return MeltQuote(
        quote=quote,
        method="bolt11",
        request=f"melt-{quote}",
        checking_id=f"mchk-{quote}",
        unit="sat",
        amount=42,
        fee_reserve=2,
        state=state,
        mint="https://mint.test",
        created_time=int(time.time()),
        expiry=int(time.time()) + 1000,
        paid_time=None,
        fee_paid=0,
        payment_preimage=None,
        change=[
            BlindedSignature(
                id="kid",
                amount=1,
                C_=PrivateKey().public_key.format().hex(),
            )
        ],
    )


@pytest.mark.asyncio
async def test_proof_crud_update_and_invalidate_flow(wallet_db: Database):
    proof = _proof("secret-a")
    await store_proof(proof, db=wallet_db)
    assert await secret_used(proof.secret, db=wallet_db)

    await update_proof(
        proof,
        db=wallet_db,
        reserved=True,
        send_id="send-1",
        mint_id="mint-1",
        melt_id="melt-1",
    )
    reserved = await get_reserved_proofs(db=wallet_db)
    assert len(reserved) == 1
    assert reserved[0].send_id == "send-1"

    filtered = await get_proofs(
        db=wallet_db, id=proof.id, mint_id="mint-1", melt_id="melt-1"
    )
    assert len(filtered) == 1
    assert filtered[0].secret == proof.secret

    await invalidate_proof(proof, db=wallet_db)
    assert not await get_proofs(db=wallet_db)
    assert not await secret_used(proof.secret, db=wallet_db)
    used = await get_proofs(db=wallet_db, table="proofs_used")
    assert len(used) == 1
    assert used[0].secret == proof.secret


@pytest.mark.asyncio
async def test_get_proofs_filters(wallet_db: Database):
    proof_a = _proof("secret-b", id="id-a", mint_id="mint-a", melt_id="melt-a")
    proof_b = _proof("secret-c", id="id-b", mint_id="mint-b", melt_id="melt-b")
    await store_proof(proof_a, db=wallet_db)
    await store_proof(proof_b, db=wallet_db)

    assert len(await get_proofs(db=wallet_db, id="id-a")) == 1
    assert len(await get_proofs(db=wallet_db, mint_id="mint-b")) == 1
    assert len(await get_proofs(db=wallet_db, melt_id="melt-a")) == 1


@pytest.mark.asyncio
async def test_keyset_and_derivation_counter_flow(wallet_db: Database):
    keyset = _keyset("keyset-derivation")
    await store_keyset(keyset, db=wallet_db)

    fetched = await get_keysets(id="keyset-derivation", db=wallet_db)
    assert len(fetched) == 1
    assert fetched[0].active is True

    keyset.active = False
    keyset.input_fee_ppk = 77
    await update_keyset(keyset, db=wallet_db)
    fetched_after = await get_keysets(id="keyset-derivation", db=wallet_db)
    assert fetched_after[0].active is False
    assert fetched_after[0].input_fee_ppk == 77

    first_counter = await bump_secret_derivation(
        db=wallet_db, keyset_id="keyset-derivation", by=3
    )
    current_counter = await bump_secret_derivation(
        db=wallet_db, keyset_id="keyset-derivation", skip=True
    )
    assert first_counter == 0
    assert current_counter == 3

    await set_secret_derivation(db=wallet_db, keyset_id="keyset-derivation", counter=9)
    set_counter = await bump_secret_derivation(
        db=wallet_db, keyset_id="keyset-derivation", skip=True
    )
    assert set_counter == 9


@pytest.mark.asyncio
async def test_delete_keyset_excludes_keyset(wallet_db: Database):
    keyset = _keyset("keyset-delete")
    await store_keyset(keyset, db=wallet_db)

    await delete_keyset(keyset_id="keyset-delete", db=wallet_db)

    assert await get_keysets(id="keyset-delete", db=wallet_db) == []
    deleted_keysets = await get_keysets(
        id="keyset-delete", db=wallet_db, exclude_deleted=False
    )
    assert len(deleted_keysets) == 1
    row = await wallet_db.fetchone(
        "SELECT deleted_at FROM keysets WHERE id = :id",
        {"id": "keyset-delete"},
    )
    assert row is not None
    assert row["deleted_at"] is not None

    deleted_keysets[0].deleted_at = None
    await update_keyset(deleted_keysets[0], db=wallet_db)
    restored_keysets = await get_keysets(id="keyset-delete", db=wallet_db)
    assert len(restored_keysets) == 1


@pytest.mark.asyncio
async def test_mint_quote_crud_lifecycle(wallet_db: Database):
    quote_1 = _mint_quote("quote-1", MintQuoteState.unpaid)
    quote_2 = _mint_quote("quote-2", MintQuoteState.pending)
    await store_bolt11_mint_quote(db=wallet_db, quote=quote_1)
    await store_bolt11_mint_quote(db=wallet_db, quote=quote_2)

    by_quote = await get_bolt11_mint_quote(db=wallet_db, quote="quote-1")
    by_request = await get_bolt11_mint_quote(db=wallet_db, request="req-quote-2")
    assert by_quote is not None and by_quote.quote == "quote-1"
    assert by_request is not None and by_request.quote == "quote-2"

    pending = await get_bolt11_mint_quotes(
        db=wallet_db, mint="https://mint.test", state=MintQuoteState.pending
    )
    assert len(pending) == 1
    assert pending[0].quote == "quote-2"

    await update_bolt11_mint_quote(
        db=wallet_db,
        quote="quote-1",
        state=MintQuoteState.paid,
        paid_time=123,
    )
    updated = await get_bolt11_mint_quote(db=wallet_db, quote="quote-1")
    assert updated is not None
    assert updated.state == MintQuoteState.paid
    assert updated.paid_time == 123

    with pytest.raises(ValueError, match="quote or request must be provided"):
        await get_bolt11_mint_quote(db=wallet_db)


@pytest.mark.asyncio
async def test_melt_quote_crud_lifecycle(wallet_db: Database):
    quote_1 = _melt_quote("mquote-1", MeltQuoteState.unpaid)
    quote_2 = _melt_quote("mquote-2", MeltQuoteState.pending)
    await store_bolt11_melt_quote(db=wallet_db, quote=quote_1)
    await store_bolt11_melt_quote(db=wallet_db, quote=quote_2)

    by_quote = await get_bolt11_melt_quote(db=wallet_db, quote="mquote-1")
    by_request = await get_bolt11_melt_quote(db=wallet_db, request="melt-mquote-2")
    assert by_quote is not None and by_quote.quote == "mquote-1"
    assert by_request is not None and by_request.quote == "mquote-2"

    pending = await get_bolt11_melt_quotes(
        db=wallet_db, mint="https://mint.test", state=MeltQuoteState.pending
    )
    assert len(pending) == 1
    assert pending[0].quote == "mquote-2"

    await update_bolt11_melt_quote(
        db=wallet_db,
        quote="mquote-1",
        state=MeltQuoteState.paid,
        paid_time=456,
        fee_paid=7,
        payment_preimage="preimage",
    )
    updated = await get_bolt11_melt_quote(db=wallet_db, quote="mquote-1")
    assert updated is not None
    assert updated.state == MeltQuoteState.paid
    assert updated.paid_time == 456
    assert updated.fee_paid == 7
    assert updated.payment_preimage == "preimage"

    with pytest.raises(ValueError, match="quote or request must be provided"):
        await get_bolt11_melt_quote(db=wallet_db)


@pytest.mark.asyncio
async def test_seed_and_mint_roundtrip(wallet_db: Database):
    await store_seed_and_mnemonic(
        db=wallet_db, seed="seed-value", mnemonic="mnemonic-value"
    )
    seed_row = await get_seed_and_mnemonic(db=wallet_db)
    assert seed_row == ("seed-value", "mnemonic-value")

    mint = WalletMint(url="https://mint.test", info='{"name":"Mint"}')
    await store_mint(db=wallet_db, mint=mint)

    mint.access_token = "access"
    mint.refresh_token = "refresh"
    mint.username = "alice"
    mint.password = "secret"
    mint.info = '{"name":"MintUpdated"}'
    await update_mint(db=wallet_db, mint=mint)

    mint_db = await get_mint_by_url(db=wallet_db, url="https://mint.test")
    assert mint_db is not None
    assert mint_db.username == "alice"
    assert mint_db.info == '{"name":"MintUpdated"}'


@pytest.mark.asyncio
async def test_get_mint_by_url_returns_none_when_missing(wallet_db: Database):
    assert await get_mint_by_url(db=wallet_db, url="https://missing.test") is None
