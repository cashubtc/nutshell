import httpx
import pytest
import pytest_asyncio
from .helpers import is_fake, is_cln, is_lnd, assert_err

BASE_URL = "http://localhost:3337"

invoice_no_amount = "lnbcrt1pnusdsqpp5fcxhgur2eewvsfy52q8xwanrjdglnf7htacp0ldeeakz6j62rj8sdqqcqzzsxqyz5vqsp5qk6l5dwhldy3gqjnr4806mtg22e25ekud4vdlf3p0hk89ud93lxs9qxpqysgq72fmgd460q04mvr5jetw7wys0vnt6ydl58gcg4jdy5jwx5d7epx8tr04et7a5yskwg4le54wrn6u6k0jjfehkc8n5spxkwxum239zxcqpuzakn"

@pytest.mark.asyncio
@pytest.mark.skipif(
    not (is_cln or is_lnd or is_fake),
    reason="only run this test on fake, lnd or cln"
)
async def test_amountless_bolt11_invoice(mint):
    response = httpx.post(
        f"{BASE_URL}/v1/melt/quote/bolt11",
        json={
            "request": invoice_no_amount,
            "unit": "sat",
            "options": {
                "amountless": {
                    "amount_msat": 100000
                }
            }
        }
    )

    assert response.status_code == 200

@pytest.mark.asyncio
@pytest.mark.skipif(
    is_cln or is_lnd or is_fake,
    reason="only run for backends where amountless is not supported"
)
async def test_unsupported_amountless_bolt11_invoice(mint):
    response = httpx.post(
        f"{BASE_URL}/v1/melt/quote/bolt11",
        json={
            "request": invoice_no_amount,
            "unit": "sat",
            "options": {
                "amountless": {
                    "amount_msat": 100000
                }
            }
        }
    )

    assert response.status_code == 400