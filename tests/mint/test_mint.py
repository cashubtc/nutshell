import time
from typing import List

import pytest

from cashu.core.base import BlindedMessage, Proof, Unit
from cashu.core.crypto.bls_dhke import step1_alice
from cashu.core.helpers import calculate_number_of_blank_outputs
from cashu.core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from tests.helpers import pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest.mark.asyncio
async def test_pubkeys(ledger: Ledger):
    assert ledger.keyset.public_keys
    assert ledger.keyset.public_keys[1].format().hex()
    assert ledger.keyset.public_keys[2 ** (settings.max_order - 1)].format().hex()


@pytest.mark.asyncio
async def test_privatekeys(ledger: Ledger):
    assert ledger.keyset.private_keys
    assert ledger.keyset.private_keys[1].to_hex()
    assert ledger.keyset.private_keys[2 ** (settings.max_order - 1)].to_hex()


@pytest.mark.asyncio
async def test_keysets(ledger: Ledger):
    assert len(ledger.keysets)
    assert len(list(ledger.keysets.keys()))
    assert ledger.keyset.id


@pytest.mark.asyncio
async def test_get_keyset(ledger: Ledger):
    keyset = ledger.get_keyset()
    assert isinstance(keyset, dict)
    assert len(keyset) == settings.max_order


@pytest.mark.asyncio
async def test_mint(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await pay_if_regtest(quote.request)
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_=step1_alice("test")[0].format().hex(),
            id=ledger.keyset.id,
        )
    ]
    promises = await ledger.mint(outputs=blinded_messages_mock, quote_id=quote.quote)
    assert len(promises)
    assert promises[0].amount == 8
    assert promises[0].C_


@pytest.mark.asyncio
async def test_mint_invalid_quote(ledger: Ledger):
    await assert_err(
        ledger.get_mint_quote(quote_id="invalid_quote_id"),
        "quote not found",
    )


@pytest.mark.asyncio
async def test_melt_invalid_quote(ledger: Ledger):
    await assert_err(
        ledger.get_melt_quote(quote_id="invalid_quote_id"),
        "quote not found",
    )


@pytest.mark.asyncio
async def test_mint_invalid_blinded_message(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await pay_if_regtest(quote.request)
    blinded_messages_mock_invalid_key = [
        BlindedMessage(
            amount=8,
            B_="039cdcd72e51c03e62be8ea970842b7076bce87d52202a72c70268336f013e03c6", # Valid curve point but not valid for BLS12-381 G1 (raises BLST_BAD_ENCODING internally since we don't have a simple invalid point) Or we can just use 02634...
            id=ledger.keyset.id,
        )
    ]
    # We will use an invalid compressed point hex for BLS
    blinded_messages_mock_invalid_key[0].B_ = "020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    await assert_err(
        ledger.mint(outputs=blinded_messages_mock_invalid_key, quote_id=quote.quote),
        "Invalid blinded message: The public key could not be parsed or is invalid.",
    )


@pytest.mark.asyncio
async def test_generate_promises(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_=step1_alice("test")[0].format().hex(),
            id=ledger.keyset.id,
        )
    ]
    await ledger._store_blinded_messages(blinded_messages_mock)
    promises = await ledger._sign_blinded_messages(blinded_messages_mock)
    assert promises[0].C_
    assert promises[0].amount == 8
    assert promises[0].id == ledger.keyset.id

    # DLEQ proof present
    assert promises[0].dleq
    assert promises[0].dleq.s
    assert promises[0].dleq.e


@pytest.mark.asyncio
async def test_generate_change_promises(ledger: Ledger):
    # Example slightly adapted from NUT-08 because we want to ensure the dynamic change
    # token amount works: `n_blank_outputs != n_returned_promises != 4`.
    # invoice_amount = 100_000
    fee_reserve = 2_000
    # total_provided = invoice_amount + fee_reserve
    actual_fee = 100

    expected_returned_promises = 7  # Amounts = [4, 8, 32, 64, 256, 512, 1024]
    expected_returned_fees = 1900

    n_blank_outputs = calculate_number_of_blank_outputs(fee_reserve)
    blinded_msgs = [step1_alice(str(n)) for n in range(n_blank_outputs)]
    outputs = [
        BlindedMessage(
            amount=1,
            B_=b.format().hex(),
            id=ledger.keyset.id,
        )
        for b, _ in blinded_msgs
    ]
    await ledger._store_blinded_messages(outputs)
    promises = await ledger._generate_change_promises(
        fee_provided=fee_reserve, fee_paid=actual_fee, outputs=outputs
    )

    assert len(promises) == expected_returned_promises
    assert sum([promise.amount for promise in promises]) == expected_returned_fees


@pytest.mark.asyncio
async def test_generate_change_promises_legacy_wallet(ledger: Ledger):
    # Check if mint handles a legacy wallet implementation (always sends 4 blank
    # outputs) as well.
    # invoice_amount = 100_000
    fee_reserve = 2_000
    # total_provided = invoice_amount + fee_reserve
    actual_fee = 100

    expected_returned_promises = 4  # Amounts = [64, 256, 512, 1024]
    expected_returned_fees = 1856

    n_blank_outputs = 4
    blinded_msgs = [step1_alice(str(n)) for n in range(n_blank_outputs)]
    outputs = [
        BlindedMessage(
            amount=1,
            B_=b.format().hex(),
            id=ledger.keyset.id,
        )
        for b, _ in blinded_msgs
    ]

    await ledger._store_blinded_messages(outputs)
    promises = await ledger._generate_change_promises(fee_reserve, actual_fee, outputs)

    assert len(promises) == expected_returned_promises
    assert sum([promise.amount for promise in promises]) == expected_returned_fees


@pytest.mark.asyncio
async def test_generate_change_promises_returns_empty_if_no_outputs(ledger: Ledger):
    # invoice_amount = 100_000
    fee_reserve = 1_000
    # total_provided = invoice_amount + fee_reserve
    actual_fee_msat = 100_000
    outputs = None

    promises = await ledger._generate_change_promises(
        fee_reserve, actual_fee_msat, outputs
    )
    assert len(promises) == 0


@pytest.mark.asyncio
async def test_get_balance(ledger: Ledger):
    unit = Unit["sat"]
    balance, fees_paid = await ledger.get_balance(unit)
    assert balance == 0
    assert fees_paid == 0


@pytest.mark.asyncio
async def test_maximum_balance(ledger: Ledger):
    settings.mint_max_balance = 1000
    await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await assert_err(
        ledger.mint_quote(PostMintQuoteRequest(amount=8000, unit="sat")),
        "Mint has reached maximum balance.",
    )
    settings.mint_max_balance = 0


@pytest.mark.asyncio
async def test_generate_change_promises_signs_subset_and_deletes_rest(ledger: Ledger):
    from cashu.core.base import BlindedMessage
    from cashu.core.crypto.bls_dhke import step1_alice
    from cashu.core.split import amount_split

    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote_resp = await ledger.mint_quote(
        PostMintQuoteRequest(amount=64, unit="sat")
    )
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote_resp.request, unit="sat")
    )
    melt_id = melt_quote_resp.quote
    fee_provided = 2_000
    fee_paid = 100
    overpaid_fee = fee_provided - fee_paid
    return_amounts = amount_split(overpaid_fee)

    # Store more blank outputs than needed for the change.
    extra_blanks = 3
    n_blank = len(return_amounts) + extra_blanks
    blank_outputs = [
        BlindedMessage(
            amount=1,
            B_=step1_alice(f"change_blank_{i}")[0].format().hex(),
            id=ledger.keyset.id,
        )
        for i in range(n_blank)
    ]
    await ledger._store_blinded_messages(blank_outputs, melt_id=melt_id)

    # Fetch the stored unsigned blanks (same as melt flow) and run change generation.
    stored_outputs = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    assert len(stored_outputs) == n_blank

    promises = await ledger._generate_change_promises(
        fee_provided=fee_provided,
        fee_paid=fee_paid,
        outputs=stored_outputs,
        melt_id=melt_id,
        keyset=ledger.keyset,
    )

    assert len(promises) == len(return_amounts)
    assert sorted(p.amount for p in promises) == sorted(return_amounts)

    # All unsigned blanks should be deleted after signing the subset.
    remaining_unsigned = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    assert remaining_unsigned == []

    # The signed promises should remain in the DB with c_ set.
    async with ledger.db.connect() as conn:
        rows = await conn.fetchall(
            f"""
            SELECT amount, c_ FROM {ledger.db.table_with_schema('promises')}
            WHERE melt_quote = :melt_id
            """,
            {"melt_id": melt_id},
        )
    assert len(rows) == len(return_amounts)
    assert all(row["c_"] for row in rows)
    assert sorted(int(row["amount"]) for row in rows) == sorted(return_amounts)


@pytest.mark.asyncio
async def test_generate_change_promises_zero_fee_deletes_all_blanks(ledger: Ledger):
    from cashu.core.base import BlindedMessage
    from cashu.core.crypto.bls_dhke import step1_alice

    # Create a real melt quote to satisfy FK on promises.melt_quote
    mint_quote_resp = await ledger.mint_quote(
        PostMintQuoteRequest(amount=64, unit="sat")
    )
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(request=mint_quote_resp.request, unit="sat")
    )
    melt_id = melt_quote_resp.quote
    fee_provided = 1_000
    fee_paid = 1_000  # no overpaid fee
    n_blank = 4
    blank_outputs = [
        BlindedMessage(
            amount=1,
            B_=step1_alice(f"no_fee_blank_{i}")[0].format().hex(),
            id=ledger.keyset.id,
        )
        for i in range(n_blank)
    ]
    await ledger._store_blinded_messages(blank_outputs, melt_id=melt_id)

    stored_outputs = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    assert len(stored_outputs) == n_blank

    promises = await ledger._generate_change_promises(
        fee_provided=fee_provided,
        fee_paid=fee_paid,
        outputs=stored_outputs,
        melt_id=melt_id,
        keyset=ledger.keyset,
    )

    assert promises == []

    remaining_unsigned = await ledger.crud.get_blinded_messages_melt_id(
        db=ledger.db, melt_id=melt_id
    )
    # With zero fee nothing is signed or deleted; blanks stay pending.
    assert len(remaining_unsigned) == n_blank

    async with ledger.db.connect() as conn:
        rows = await conn.fetchall(
            f"""
            SELECT amount, c_ FROM {ledger.db.table_with_schema('promises')}
            WHERE melt_quote = :melt_id
            """,
            {"melt_id": melt_id},
        )
    assert len(rows) == n_blank
    assert all(row["c_"] is None for row in rows)


@pytest.mark.asyncio
async def test_mint_quote_ttl_setting_overrides_invoice_expiry(ledger: Ledger):
    ttl = 900  # 15 minutes
    settings.mint_quote_ttl = ttl
    try:
        before = int(time.time())
        quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
        after = int(time.time())
        assert quote.expiry is not None
        assert before + ttl <= quote.expiry <= after + ttl
    finally:
        settings.mint_quote_ttl = None


@pytest.mark.asyncio
async def test_melt_quote_ttl_setting_overrides_invoice_expiry(ledger: Ledger):
    ttl = 600  # 10 minutes
    settings.melt_quote_ttl = ttl
    try:
        mint_quote = await ledger.mint_quote(PostMintQuoteRequest(amount=64, unit="sat"))
        before = int(time.time())
        melt_quote = await ledger.melt_quote(
            PostMeltQuoteRequest(request=mint_quote.request, unit="sat")
        )
        after = int(time.time())
        assert melt_quote.expiry is not None
        assert before + ttl <= melt_quote.expiry <= after + ttl
    finally:
        settings.melt_quote_ttl = None


@pytest.mark.asyncio
async def test_mint_bls_infinity_dos(ledger: Ledger):
    from cashu.core.base import BlindedMessage, MintKeyset
    from cashu.core.errors import TransactionError
    
    keyset = MintKeyset(seed="TEST_PRIVATE_KEY", derivation_path="m/0'/0'/0'", version="0.21.0", unit="sat")
    keyset.active = True
    ledger.keysets[keyset.id] = keyset
    
    infinity_b_ = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    
    outputs = [
        BlindedMessage(amount=1, B_=infinity_b_, id=keyset.id)
    ]
    
    with pytest.raises(TransactionError) as exc_info:
        await ledger._sign_blinded_messages(outputs)
    
    assert "point at infinity" in str(exc_info.value)
