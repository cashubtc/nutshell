from types import SimpleNamespace
from typing import Type

import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResponse, PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet


def _quote(request: str, amount: int, unit: str) -> MeltQuote:
    return MeltQuote(
        quote="q1",
        method="bolt11",
        request=request,
        checking_id="checking-1",
        unit=unit,
        amount=amount,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wallet_cls", "decode_path"),
    [
        (LndRPCWallet, "cashu.lightning.lnd_grpc.lnd_grpc.bolt11.decode"),
        (LndRestWallet, "cashu.lightning.lndrest.bolt11.decode"),
    ],
)
async def test_lnd_mpp_preserves_msat_quote_amount_unit(
    monkeypatch: pytest.MonkeyPatch,
    wallet_cls: Type[LndRPCWallet] | Type[LndRestWallet],
    decode_path: str,
):
    wallet = object.__new__(wallet_cls)
    wallet.supports_mpp = True
    captured: dict[str, Amount | int] = {}

    async def pay_partial_invoice(
        quote: MeltQuote, amount: Amount, fee_limit_msat: int
    ) -> PaymentResponse:
        captured["amount"] = amount
        captured["fee_limit_msat"] = fee_limit_msat
        return PaymentResponse(result=PaymentResult.SETTLED)

    monkeypatch.setattr(wallet, "pay_partial_invoice", pay_partial_invoice)
    monkeypatch.setattr(
        decode_path,
        lambda request: SimpleNamespace(amount_msat=2_000),
    )

    await wallet.pay_invoice(
        _quote("lnbc1fake", amount=1_000, unit="msat"), fee_limit_msat=123
    )

    assert captured["amount"] == Amount(Unit.msat, 1_000)
    assert captured["fee_limit_msat"] == 123
