from types import SimpleNamespace
from typing import Type

import pytest

from cashu.core.base import Amount, MeltQuote, MeltQuoteState, Unit
from cashu.lightning.base import PaymentResponse, PaymentResult
from cashu.lightning.lnd_grpc.lnd_grpc import LndRPCWallet
from cashu.lightning.lndrest import LndRestWallet


def _quote(request: str, amount: int, unit: str, amount_msat: int) -> MeltQuote:
    return MeltQuote(
        quote="q1",
        method="bolt11",
        request=request,
        checking_id="checking-1",
        unit=unit,
        amount=amount,
        amount_msat=amount_msat,
        amount_option_type="nut-15",
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
@pytest.mark.parametrize("unit,amount", [("sat", 17), ("msat", 16_001)])
async def test_lnd_mpp_preserves_msat_quote_amount_unit(
    monkeypatch: pytest.MonkeyPatch,
    wallet_cls: Type[LndRPCWallet] | Type[LndRestWallet],
    decode_path: str,
    unit: str,
    amount: int,
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
        lambda request: SimpleNamespace(amount_msat=17_000),
    )

    await wallet.pay_invoice(
        _quote("lnbc1fake", amount=amount, unit=unit, amount_msat=16_001),
        fee_limit_msat=123,
    )

    assert captured["amount"] == Amount(Unit.msat, 16_001)
    assert captured["fee_limit_msat"] == 123
