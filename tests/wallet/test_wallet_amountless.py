import hashlib

import bolt11
import httpx
import pytest
from click.testing import CliRunner

from cashu.core.base import Unit
from cashu.core.settings import settings
from cashu.wallet.cli.cli import cli
from cashu.wallet.lightning import LightningWallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    docker_lightning_cli,
    get_real_invoice,
    is_fake,
    pay_if_regtest,
    run_cmd_json,
)
from tests.mint.test_mint_invoice_amount import invoice_response


def amountless_invoice():
    if is_fake:
        return invoice_response(None).payment_request
    return get_real_invoice(0)["payment_request"]


@pytest.mark.asyncio
@pytest.mark.skipif(
    settings.mint_backend_bolt11_sat
    not in {"FakeWallet", "LndRestWallet", "LndRPCWallet", "CLNRestWallet"},
    reason="requires an amountless-capable backend",
)
@pytest.mark.parametrize("amount_msat", [16_000, 16_001])
async def test_wallet_pays_amountless_invoice_end_to_end(tmp_path, amount_msat):
    wallet = await LightningWallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path))
    await wallet.load_mint()
    assert wallet.mint_info.supports_amountless("bolt11", Unit.sat)
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    invoice = amountless_invoice()
    decoded = bolt11.decode(invoice)
    assert not decoded.amount_msat

    response = await wallet.pay_invoice(invoice, amount_msat=amount_msat)
    assert response.settled, response.error_message
    assert response.preimage
    assert response.checking_id == decoded.payment_hash
    status = await wallet.get_payment_status(invoice)
    assert status.settled
    # The quote charges rounded-up sats; unused fee reserve is returned as change.
    amount_sat = (amount_msat + 999) // 1000
    expected_fee_sat = 1 if is_fake else 0  # direct regtest channel
    assert wallet.balance == 64 - amount_sat - expected_fee_sat
    await wallet.load_proofs(reload=True)
    assert wallet.balance == 64 - amount_sat - expected_fee_sat
    if not is_fake:
        received = run_cmd_json(
            [*docker_lightning_cli, "lookupinvoice", decoded.payment_hash]
        )
        assert received["state"] == "SETTLED"
        assert int(received["amt_paid_msat"]) == amount_msat
        assert (
            hashlib.sha256(bytes.fromhex(response.preimage)).hexdigest()
            == decoded.payment_hash
        )


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="FakeWallet API validation")
async def test_amountless_api_rejects_missing_and_invalid_amounts():
    invoice = amountless_invoice()
    async with httpx.AsyncClient(base_url=SERVER_ENDPOINT) as client:
        missing = await client.post(
            "/v1/melt/quote/bolt11", json={"unit": "sat", "request": invoice}
        )
        assert missing.status_code == 400
        assert "amountless" in missing.json()["detail"]
        invalid = await client.post(
            "/v1/melt/quote/bolt11",
            json={
                "unit": "sat",
                "request": invoice,
                "options": {"amountless": {"amount_msat": 0}},
            },
        )
        assert invalid.status_code == 422


@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="FakeWallet capability checks")
async def test_wallet_requires_amount_and_support(tmp_path):
    wallet = await LightningWallet.with_db(url=SERVER_ENDPOINT, db=str(tmp_path))
    await wallet.load_mint()
    invoice = amountless_invoice()
    with pytest.raises(ValueError, match="requires an amount"):
        await wallet.melt_quote(invoice)
    for method in wallet.mint_info.nuts[5]["methods"]:
        method.pop("options", None)
    with pytest.raises(ValueError, match="does not support amountless"):
        await wallet.melt_quote(invoice, 16_000)


@pytest.mark.skipif(not is_fake, reason="CLI funding requires FakeWallet auto-payment")
def test_cli_pays_amountless_invoice_end_to_end():
    runner = CliRunner()
    prefix = ["--wallet", "test_amountless_cli", "--host", settings.mint_url, "--tests"]
    funding = runner.invoke(cli, [*prefix, "invoice", "64"])
    assert funding.exit_code == 0, funding.output
    # The CLI invoice command stores the quote; `invoices --mint` claims it.
    claim = runner.invoke(cli, [*prefix, "invoices", "--mint"])
    assert claim.exit_code == 0, claim.output
    invoice = amountless_invoice()
    paid = runner.invoke(cli, [*prefix, "pay", invoice, "16", "--yes"])
    assert paid.exit_code == 0, paid.output
    assert "Invoice paid." in paid.output
