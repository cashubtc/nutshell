import copy
from typing import List, Union

import pytest
import pytest_asyncio

from cashu.core.base import MintQuoteState, Proof
from cashu.core.errors import CashuError, KeysetNotFoundError
from cashu.core.helpers import sum_proofs
from cashu.core.settings import settings
from cashu.wallet.crud import (
    get_bolt11_melt_quote,
    get_bolt11_mint_quote,
    get_keysets,
    get_proofs,
)
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    get_real_invoice,
    is_fake,
    is_github_actions,
    is_regtest,
    pay_if_regtest,
)


async def assert_err(f, msg: Union[str, CashuError]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        error_message: str = str(exc.args[0])
        if isinstance(msg, CashuError):
            if msg.detail not in error_message:
                raise Exception(
                    f"CashuError. Expected error: {msg.detail}, got: {error_message}"
                )
            return
        if msg not in error_message:
            raise Exception(f"Expected error: {msg}, got: {error_message}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


async def assert_err_multiple(f, msgs: List[str]):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        for msg in msgs:
            if msg in str(exc.args[0]):
                return
        raise Exception(f"Expected error: {msgs}, got: {exc.args[0]}")
    raise Exception(f"Expected error: {msgs}, got no error")


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert sum([p.amount for p in proofs]) == expected


async def reset_wallet_db(wallet: Wallet):
    await wallet.db.execute("DELETE FROM proofs")
    await wallet.db.execute("DELETE FROM proofs_used")
    await wallet.db.execute("DELETE FROM keysets")
    await wallet.load_mint()


@pytest_asyncio.fixture(scope="function")
async def wallet1(mint):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet2.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet2",
        name="wallet2",
    )
    await wallet2.load_mint()
    yield wallet2


@pytest.mark.asyncio
async def test_get_keys(wallet1: Wallet):
    assert wallet1.keysets[wallet1.keyset_id].public_keys
    assert len(wallet1.keysets[wallet1.keyset_id].public_keys) == settings.max_order
    keysets = await wallet1._get_keys()
    keyset = keysets[0]
    assert keyset.id is not None
    # assert keyset.id_deprecated == "eGnEWtdJ0PIM"
    assert keyset.id == "009a1f293253e41e"
    assert isinstance(keyset.id, str)
    assert len(keyset.id) > 0


@pytest.mark.asyncio
async def test_get_keyset(wallet1: Wallet):
    assert wallet1.keysets[wallet1.keyset_id].public_keys
    assert len(wallet1.keysets[wallet1.keyset_id].public_keys) == settings.max_order
    # let's get the keys first so we can get a keyset ID that we use later
    keysets = await wallet1._get_keys()
    keyset = keysets[0]
    # gets the keys of a specific keyset
    assert keyset.id is not None
    assert keyset.public_keys is not None
    keys2 = await wallet1._get_keyset(keyset.id)
    assert keys2.public_keys is not None
    assert len(keyset.public_keys) == len(keys2.public_keys)


@pytest.mark.asyncio
async def test_get_keyset_from_db(wallet1: Wallet):
    # first load it from the mint
    # await wallet1.activate_keyset()
    # NOTE: conftest already called wallet.load_mint() which got the keys from the mint
    keyset1 = copy.copy(wallet1.keysets[wallet1.keyset_id])

    # then load it from the db
    await wallet1.activate_keyset()
    keyset2 = copy.copy(wallet1.keysets[wallet1.keyset_id])

    assert keyset1.public_keys == keyset2.public_keys
    assert keyset1.id == keyset2.id

    # load it directly from the db
    keysets_local = await get_keysets(db=wallet1.db, id=keyset1.id)
    assert keysets_local[0]
    keyset3 = keysets_local[0]
    assert keyset1.public_keys == keyset3.public_keys
    assert keyset1.id == keyset3.id


@pytest.mark.asyncio
async def test_get_info(wallet1: Wallet):
    info = await wallet1._get_info()
    assert info.name


@pytest.mark.asyncio
async def test_get_nonexistent_keyset(wallet1: Wallet):
    await assert_err(
        wallet1._get_keyset("nonexistent"),
        KeysetNotFoundError(),
    )


@pytest.mark.asyncio
async def test_get_keysets(wallet1: Wallet):
    keysets = await wallet1._get_keysets()
    assert isinstance(keysets, list)
    assert len(keysets) > 0
    assert wallet1.keyset_id in [k.id for k in keysets]


@pytest.mark.asyncio
async def test_request_mint(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    assert mint_quote.request


@pytest.mark.asyncio
async def test_mint(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    if not settings.debug_mint_only_deprecated:
        quote_resp = await wallet1.get_mint_quote(mint_quote.quote)
        assert quote_resp.request == mint_quote.request
        assert quote_resp.state == MintQuoteState.paid.value

    expected_proof_amounts = wallet1.split_wallet_state(64)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64

    # verify that proofs in proofs_used db have the same mint_id as the invoice in the db
    mint_quote_2 = await get_bolt11_mint_quote(db=wallet1.db, quote=mint_quote.quote)
    assert mint_quote_2
    proofs_minted = await get_proofs(
        db=wallet1.db, mint_id=mint_quote_2.quote, table="proofs"
    )
    assert len(proofs_minted) == len(expected_proof_amounts)
    assert all([p.amount in expected_proof_amounts for p in proofs_minted])
    assert all([p.mint_id == mint_quote_2.quote for p in proofs_minted])


@pytest.mark.asyncio
async def test_mint_amounts(wallet1: Wallet):
    """Mint predefined amounts"""
    amts = [1, 1, 1, 2, 2, 4, 16]
    mint_quote = await wallet1.request_mint(sum(amts))
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(amount=sum(amts), split=amts, quote_id=mint_quote.quote)
    assert wallet1.balance == 27
    assert wallet1.proof_amounts == amts


@pytest.mark.asyncio
async def test_mint_amounts_wrong_sum(wallet1: Wallet):
    """Mint predefined amounts"""

    amts = [1, 1, 1, 2, 2, 4, 16]
    mint_quote = await wallet1.request_mint(sum(amts))
    await assert_err(
        wallet1.mint(amount=sum(amts) + 1, split=amts, quote_id=mint_quote.quote),
        "split must sum to amount",
    )


@pytest.mark.asyncio
async def test_mint_amounts_wrong_order(wallet1: Wallet):
    """Mint amount that is not part in 2^n"""
    amts = [1, 2, 3]
    mint_quote = await wallet1.request_mint(sum(amts))
    allowed_amounts = wallet1.get_allowed_amounts()
    await assert_err(
        wallet1.mint(amount=sum(amts), split=[1, 2, 3], quote_id=mint_quote.quote),
        f"Can only mint amounts supported by the mint: {allowed_amounts}",
    )


@pytest.mark.asyncio
async def test_split(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64
    # the outputs we keep that we expect after the split
    expected_proof_amounts = wallet1.split_wallet_state(44)
    p1, p2 = await wallet1.split(wallet1.proofs, 20)
    assert wallet1.balance == 64
    assert sum_proofs(p1) == 44
    # what we keep should have the expected amounts
    assert [p.amount for p in p1] == expected_proof_amounts
    assert sum_proofs(p2) == 20
    # what we send should be the optimal split
    assert [p.amount for p in p2] == [4, 16]
    assert all([p.id == wallet1.keyset_id for p in p1])
    assert all([p.id == wallet1.keyset_id for p in p2])


@pytest.mark.asyncio
async def test_swap_to_send(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64

    # this will select 32 sats and them (nothing to keep)
    keep_proofs, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    assert_amt(send_proofs, 32)
    assert_amt(keep_proofs, 0)

    spendable_proofs = wallet1.coinselect(wallet1.proofs, 32)
    assert sum_proofs(spendable_proofs) == 32

    assert sum_proofs(send_proofs) == 32
    assert wallet1.balance == 64
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_split_more_than_balance(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await assert_err(
        wallet1.split(wallet1.proofs, 128),
        # "Mint Error: inputs do not have same amount as outputs",
        "amount too large.",
    )
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_melt(wallet1: Wallet):
    # mint twice so we have enough to pay the second invoice back
    topup_mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(topup_mint_quote.request)
    await wallet1.mint(128, quote_id=topup_mint_quote.quote)
    assert wallet1.balance == 128

    invoice_payment_request = ""
    if is_regtest:
        invoice_dict = get_real_invoice(64)
        invoice_payment_request = invoice_dict["payment_request"]

    if is_fake:
        mint_quote = await wallet1.request_mint(64)
        invoice_payment_request = mint_quote.request

    quote = await wallet1.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve

    if is_regtest:
        # we expect a fee reserve of 2 sat for regtest
        assert total_amount == 66
        assert quote.fee_reserve == 2
    if is_fake:
        # we expect a fee reserve of 0 sat for fake
        assert total_amount == 64
        assert quote.fee_reserve == 0

    if not settings.debug_mint_only_deprecated:
        quote_resp = await wallet1.get_melt_quote(quote.quote)
        assert quote_resp.amount == quote.amount

    _, send_proofs = await wallet1.swap_to_send(wallet1.proofs, total_amount)

    melt_response = await wallet1.melt(
        proofs=send_proofs,
        invoice=invoice_payment_request,
        fee_reserve_sat=quote.fee_reserve,
        quote_id=quote.quote,
    )

    if is_regtest:
        assert melt_response.change, "No change returned"
        assert len(melt_response.change) == 1, "More than one change returned"
        # NOTE: we assume that we will get a token back from the same keyset as the ones we melted
        # this could be wrong if we melted tokens from an old keyset but the returned ones are
        # from a newer one.
        assert melt_response.change[0].id == send_proofs[0].id, "Wrong keyset returned"

    # verify that proofs in proofs_used db have the same melt_id as the invoice in the db
    melt_quote_db = await get_bolt11_melt_quote(
        db=wallet1.db, request=invoice_payment_request
    )
    assert melt_quote_db, "No invoice in db"
    proofs_used = await get_proofs(
        db=wallet1.db, melt_id=melt_quote_db.quote, table="proofs_used"
    )

    assert len(proofs_used) == len(send_proofs), "Not all proofs used"
    assert all([p.melt_id == melt_quote_db.quote for p in proofs_used]), "Wrong melt_id"

    # the payment was without fees so we need to remove it from the total amount
    assert wallet1.balance == 128 - (total_amount - quote.fee_reserve), "Wrong balance"
    assert wallet1.balance == 64, "Wrong balance"


@pytest.mark.asyncio
async def test_swap_to_send_more_than_balance(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await assert_err(
        wallet1.swap_to_send(wallet1.proofs, 128, set_reserved=True),
        "Balance too low",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_double_spend(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    doublespend = await wallet1.mint(64, quote_id=mint_quote.quote)
    await wallet1.split(wallet1.proofs, 20)
    await assert_err(
        wallet1.split(doublespend, 20),
        "Token already spent.",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
async def test_duplicate_proofs_double_spent(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    doublespend = await wallet1.mint(64, quote_id=mint_quote.quote)
    await assert_err(
        wallet1.split(wallet1.proofs + doublespend, 20),
        "Mint Error: Duplicate inputs provided",
    )
    assert wallet1.balance == 64
    assert wallet1.available_balance == 64


@pytest.mark.asyncio
@pytest.mark.skipif(is_github_actions, reason="GITHUB_ACTIONS")
async def test_split_race_condition(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    # run two splits in parallel
    import asyncio

    await assert_err_multiple(
        asyncio.gather(
            wallet1.split(wallet1.proofs, 20),
            wallet1.split(wallet1.proofs, 20),
        ),
        ["proofs are pending.", "already spent."],
    )


@pytest.mark.asyncio
async def test_send_and_redeem(wallet1: Wallet, wallet2: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    _, spendable_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 32, set_reserved=True
    )
    await wallet2.redeem(spendable_proofs)
    assert wallet2.balance == 32

    assert wallet1.balance == 64
    assert wallet1.available_balance == 32
    await wallet1.invalidate(spendable_proofs)
    assert wallet1.balance == 32
    assert wallet1.available_balance == 32


@pytest.mark.asyncio
async def test_invalidate_all_proofs(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet. Should not work!"""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await wallet1.invalidate(wallet1.proofs)
    assert wallet1.balance == 0


@pytest.mark.asyncio
async def test_invalidate_unspent_proofs_with_checking(wallet1: Wallet):
    """Try to invalidate proofs that have not been spent yet but force no check."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await wallet1.invalidate(wallet1.proofs, check_spendable=True)
    assert wallet1.balance == 64


@pytest.mark.asyncio
async def test_split_invalid_amount(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    await assert_err(
        wallet1.split(wallet1.proofs, -1),
        "amount can't be negative",
    )


@pytest.mark.asyncio
async def test_token_state(wallet1: Wallet):
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)
    assert wallet1.balance == 64
    resp = await wallet1.check_proof_state(wallet1.proofs)
    assert resp.states[0].state.value == "UNSPENT"


@pytest.mark.asyncio
async def testactivate_keyset_specific_keyset(wallet1: Wallet):
    await wallet1.activate_keyset()
    assert list(wallet1.keysets.keys()) == ["009a1f293253e41e"]
    await wallet1.activate_keyset(keyset_id=wallet1.keyset_id)
    await wallet1.activate_keyset(keyset_id="009a1f293253e41e")
    # expect deprecated keyset id to be present
    await assert_err(
        wallet1.activate_keyset(keyset_id="nonexistent"),
        KeysetNotFoundError("nonexistent"),
    )
