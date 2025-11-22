from typing import Optional

import pytest
import pytest_asyncio

from cashu.mint.ledger import Ledger
from cashu.wallet.errors import InputFeeExceedsLimitError
from cashu.wallet.wallet import Wallet
from cashu.wallet.wallet import Wallet as Wallet1
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


@pytest_asyncio.fixture(scope="function")
async def wallet1(ledger: Ledger):
    wallet1 = await Wallet1.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet1",
        name="wallet1",
    )
    await wallet1.load_mint()
    yield wallet1


def set_ledger_keyset_fees(
    fee_ppk: int, ledger: Ledger, wallet: Optional[Wallet] = None
):
    for keyset in ledger.keysets.values():
        keyset.input_fee_ppk = fee_ppk

    if wallet:
        for wallet_keyset in wallet.keysets.values():
            wallet_keyset.input_fee_ppk = fee_ppk


@pytest.mark.asyncio
async def test_send_with_input_fee_limit(wallet1: Wallet, ledger: Ledger):
    """
    This test checks that the --max-input-fee parameter works as expected, by
    blocking transactions that generate too many fees

    A token with a single 64-sat proof is requested
    """
    # set fees to 5000 ppk, i.e. 5 sats per token
    set_ledger_keyset_fees(5000, ledger, wallet1)
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote, split=[64])  # a single token

    # Test with restrictive limit (should fail)
    # The fees are 5000 millisats, we'll try with a restrictive limit and then relax it
    # until it's working:
    with pytest.raises(InputFeeExceedsLimitError) as exc_info:
        await wallet1.select_to_send(wallet1.proofs, 3, max_input_fee_ppk=0)

    assert exc_info.value.actual_fee_ppk == 5000, exc_info.value
    assert exc_info.value.max_fee_ppk == 0, exc_info.value

    with pytest.raises(InputFeeExceedsLimitError) as exc_info:
        await wallet1.select_to_send(wallet1.proofs, 3, max_input_fee_ppk=4999)

    assert exc_info.value.actual_fee_ppk == 5000, exc_info.value
    assert exc_info.value.max_fee_ppk == 4999, exc_info.value

    # Test with generous limit (should succeed)
    # Limit of 5000 ppk should succeed

    # HOWEVER, this next line generates an error that I don't understand:
    #   Exception: Mint Error: inputs (64) - fees (0) vs outputs (59) are not balanced. (Code: 11000)
    # Why does it say the fees are 0 in that error message?
    send_proofs, _ = await wallet1.select_to_send(
        wallet1.proofs, 3, max_input_fee_ppk=5000
    )
    fees = ledger.get_fees_for_proofs(send_proofs)
    assert fees == 5
