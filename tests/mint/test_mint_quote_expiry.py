import secrets
import time

import pytest

from cashu.core.base import BlindedMessage, MintQuote
from cashu.core.crypto.b_dhke import step1_alice
from cashu.core.models import PostMintBatchRequest, PostMintQuoteRequest
from cashu.mint.ledger import Ledger
from tests.helpers import pay_if_regtest


@pytest.mark.asyncio
@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
async def test_paid_quote_can_be_minted_after_expiry(
    ledger: Ledger, monkeypatch: pytest.MonkeyPatch, batch: bool
):
    quote = await ledger.mint_quote(PostMintQuoteRequest(amount=8, unit="sat"))
    await pay_if_regtest(quote.request)

    # mint_quotes has no expiry column, so expire the quotes the ledger loads.
    from_row = MintQuote.from_row

    def expired_from_row(row) -> MintQuote:
        loaded = from_row(row)
        loaded.expiry = int(time.time()) - 1
        return loaded

    monkeypatch.setattr(MintQuote, "from_row", expired_from_row)

    loaded = await ledger.get_mint_quote(quote.quote)
    assert loaded.paid
    assert loaded.expiry and loaded.expiry < int(time.time())

    blinded_message, _ = step1_alice(secrets.token_hex(16))
    outputs = [
        BlindedMessage(amount=8, B_=blinded_message.format().hex(), id=ledger.keyset.id)
    ]
    if batch:
        promises = await ledger.mint_batch(
            PostMintBatchRequest(quotes=[quote.quote], outputs=outputs)
        )
    else:
        promises = await ledger.mint(outputs=outputs, quote_id=quote.quote)

    assert [promise.amount for promise in promises] == [8]
    assert (await ledger.get_mint_quote(quote.quote)).issued
