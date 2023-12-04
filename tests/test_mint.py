from typing import List

import pytest

from cashu.core.base import BlindedMessage, PostMintQuoteRequest, Proof
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.helpers import calculate_number_of_blank_outputs
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
        ledger.keyset.public_keys[1].serialize().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )
    assert (
        ledger.keyset.public_keys[2 ** (settings.max_order - 1)].serialize().hex()
        == "023c84c0895cc0e827b348ea0a62951ca489a5e436f3ea7545f3c1d5f1bea1c866"
    )


@pytest.mark.asyncio
async def test_privatekeys(ledger: Ledger):
    assert ledger.keyset.private_keys
    assert (
        ledger.keyset.private_keys[1].serialize()
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    assert (
        ledger.keyset.private_keys[2 ** (settings.max_order - 1)].serialize()
        == "b0477644cb3d82ffcc170bc0a76e0409727232e87c5ae51d64a259936228c7be"
    )


@pytest.mark.asyncio
async def test_keysets(ledger: Ledger):
    assert len(ledger.keysets)
    assert len(list(ledger.keysets.keys()))
    assert ledger.keyset.id == "009a1f293253e41e"


@pytest.mark.asyncio
async def test_keysets_backwards_compatibility_pre_v0_15(ledger: Ledger):
    """Backwards compatibility test for keysets pre v0.15.0
    We expect two instances of the same keyset but with different IDs.
    First one is the new hex ID, second one is the old base64 ID.
    """
    assert len(ledger.keysets) == 2
    assert list(ledger.keysets.keys()) == ["009a1f293253e41e", "eGnEWtdJ0PIM"]
    assert ledger.keyset.id == "009a1f293253e41e"


@pytest.mark.asyncio
async def test_get_keyset(ledger: Ledger):
    keyset = ledger.get_keyset()
    assert isinstance(keyset, dict)
    assert len(keyset) == settings.max_order


@pytest.mark.asyncio
async def test_mint(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    pay_if_regtest(quote.request)
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="009a1f293253e41e",
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
async def test_mint_invalid_blinded_message(ledger: Ledger):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    pay_if_regtest(quote.request)
    blinded_messages_mock_invalid_key = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bff02d7fa2365379b0840afe249a7a9d71237",
            id="009a1f293253e41e",
        )
    ]
    await assert_err(
        ledger.mint(outputs=blinded_messages_mock_invalid_key, quote_id=quote.quote),
        "invalid public key",
    )


@pytest.mark.asyncio
async def test_generate_promises(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="009a1f293253e41e",
        )
    ]
    promises = await ledger._generate_promises(blinded_messages_mock)
    assert (
        promises[0].C_
        == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    )
    assert promises[0].amount == 8
    assert promises[0].id == "009a1f293253e41e"

    # DLEQ proof present
    assert promises[0].dleq
    assert promises[0].dleq.s
    assert promises[0].dleq.e


@pytest.mark.asyncio
async def test_generate_promises_deprecated_keyset_id(ledger: Ledger):
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="eGnEWtdJ0PIM",
        )
    ]
    promises = await ledger._generate_promises(blinded_messages_mock)
    assert (
        promises[0].C_
        == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    )
    assert promises[0].amount == 8
    assert promises[0].id == "eGnEWtdJ0PIM"

    # DLEQ proof present
    assert promises[0].dleq
    assert promises[0].dleq.s
    assert promises[0].dleq.e


@pytest.mark.asyncio
async def test_generate_promises_keyset_backwards_compatibility_pre_v0_15(
    ledger: Ledger,
):
    """Backwards compatibility test for keysets pre v0.15.0
    We want to generate promises using the old keyset ID.
    We expect the promise to have the old base64 ID.
    """
    blinded_messages_mock = [
        BlindedMessage(
            amount=8,
            B_="02634a2c2b34bec9e8a4aba4361f6bf202d7fa2365379b0840afe249a7a9d71239",
            id="eGnEWtdJ0PIM",
        )
    ]
    promises = await ledger._generate_promises(
        blinded_messages_mock, keyset=ledger.keysets["eGnEWtdJ0PIM"]
    )
    assert (
        promises[0].C_
        == "031422eeffb25319e519c68de000effb294cb362ef713a7cf4832cea7b0452ba6e"
    )
    assert promises[0].amount == 8
    assert promises[0].id == "eGnEWtdJ0PIM"


@pytest.mark.asyncio
async def test_generate_change_promises(ledger: Ledger):
    # Example slightly adapted from NUT-08 because we want to ensure the dynamic change
    # token amount works: `n_blank_outputs != n_returned_promises != 4`.
    invoice_amount = 100_000
    fee_reserve = 2_000
    total_provided = invoice_amount + fee_reserve
    actual_fee = 100

    expected_returned_promises = 7  # Amounts = [4, 8, 32, 64, 256, 512, 1024]
    expected_returned_fees = 1900

    n_blank_outputs = calculate_number_of_blank_outputs(fee_reserve)
    blinded_msgs = [step1_alice(str(n)) for n in range(n_blank_outputs)]
    outputs = [
        BlindedMessage(
            amount=1,
            B_=b.serialize().hex(),
            id="009a1f293253e41e",
        )
        for b, _ in blinded_msgs
    ]

    promises = await ledger._generate_change_promises(
        total_provided, invoice_amount, actual_fee, outputs
    )

    assert len(promises) == expected_returned_promises
    assert sum([promise.amount for promise in promises]) == expected_returned_fees


@pytest.mark.asyncio
async def test_generate_change_promises_legacy_wallet(ledger: Ledger):
    # Check if mint handles a legacy wallet implementation (always sends 4 blank
    # outputs) as well.
    invoice_amount = 100_000
    fee_reserve = 2_000
    total_provided = invoice_amount + fee_reserve
    actual_fee = 100

    expected_returned_promises = 4  # Amounts = [64, 256, 512, 1024]
    expected_returned_fees = 1856

    n_blank_outputs = 4
    blinded_msgs = [step1_alice(str(n)) for n in range(n_blank_outputs)]
    outputs = [
        BlindedMessage(
            amount=1,
            B_=b.serialize().hex(),
            id="009a1f293253e41e",
        )
        for b, _ in blinded_msgs
    ]

    promises = await ledger._generate_change_promises(
        total_provided, invoice_amount, actual_fee, outputs
    )

    assert len(promises) == expected_returned_promises
    assert sum([promise.amount for promise in promises]) == expected_returned_fees


@pytest.mark.asyncio
async def test_generate_change_promises_returns_empty_if_no_outputs(ledger: Ledger):
    invoice_amount = 100_000
    fee_reserve = 1_000
    total_provided = invoice_amount + fee_reserve
    actual_fee_msat = 100_000
    outputs = None

    promises = await ledger._generate_change_promises(
        total_provided, invoice_amount, actual_fee_msat, outputs
    )
    assert len(promises) == 0


@pytest.mark.asyncio
async def test_get_balance(ledger: Ledger):
    balance = await ledger.get_balance()
    assert balance == 0


@pytest.mark.asyncio
async def test_maximum_balance(ledger: Ledger):
    settings.mint_max_balance = 1000
    await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await assert_err(
        ledger.mint_quote(PostMintQuoteRequest(amount=8000, unit="sat")),
        "Mint has reached maximum balance.",
    )
    settings.mint_max_balance = 0
