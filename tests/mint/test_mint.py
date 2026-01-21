from typing import List

import pytest

from cashu.core.base import BlindedMessage, Proof, Unit
from cashu.core.crypto.b_dhke import step1_alice
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
    assert (
        ledger.keyset.public_keys[1].format().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
    assert (
        ledger.keyset.public_keys[2 ** (settings.max_order - 1)].format().hex()
        == "023c84c0895cc0e827b348ea0a62951ca489a5e436f3ea7545f3c1d5f1bea1c866"
    )


@pytest.mark.asyncio
async def test_privatekeys(ledger: Ledger):
    assert ledger.keyset.private_keys
    assert (
        ledger.keyset.private_keys[1].to_hex()
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    assert (
        ledger.keyset.private_keys[2 ** (settings.max_order - 1)].to_hex()
        == "b0477644cb3d82ffcc170bc0a76e0409727232e87c5ae51d64a259936228c7be"
    )


@pytest.mark.asyncio
async def test_keysets(ledger: Ledger):
    assert len(ledger.keysets)
    assert len(list(ledger.keysets.keys()))
    assert ledger.keyset.id == "01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc"


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
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc",
        )
    ]
    promises = await ledger.mint(outputs=blinded_messages_mock, quote_id=quote.quote)
    assert len(promises)
    assert promises[0].amount == 8
    assert (
        promises[0].C_
        == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    )


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
            B_="02634a2c2b34bec9e8a4aba4361f6bff02d7fa2365379b0840afe249a7a9d71237",
            id="01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc",
        )
    ]
    await assert_err(
        ledger.mint(outputs=blinded_messages_mock_invalid_key, quote_id=quote.quote),
        "The public key could not be parsed or is invalid.",
    )


@pytest.mark.asyncio
async def test_generate_promises(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc",
        )
    ]
    await ledger._store_blinded_messages(blinded_messages_mock)
    promises = await ledger._sign_blinded_messages(blinded_messages_mock)
    assert (
        promises[0].C_
        == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    )
    assert promises[0].amount == 8
    assert promises[0].id == "01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc"

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
            id="01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc",
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
            id="01d8a63077d0a51f9855f066409782ffcb322dc8a2265291865221ed06c039f6bc",
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
    from cashu.core.crypto.b_dhke import step1_alice
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
    from cashu.core.crypto.b_dhke import step1_alice

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
