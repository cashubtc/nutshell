from types import SimpleNamespace
from typing import Any, cast

import pytest

from cashu.core.base import MeltQuote, MeltQuoteState, MintQuote, MintQuoteState, Unit
from cashu.core.mint_info import MintInfo
from cashu.core.settings import settings
from cashu.mint.management_rpc import management_rpc as rpc_module


def _rpc_with_ledger(ledger=None):
    ledger = ledger or SimpleNamespace(
        mint_info=MintInfo(
            name="Mint",
            pubkey=None,
            version="1.0",
            description="d",
            description_long="long",
            contact=[],
            motd="motd",
            icon_url=None,
            urls=None,
            tos_url=None,
            time=None,
            nuts={},
        )
    )
    return rpc_module.MintManagementRPC(ledger=ledger)


def test_get_info_serializes_mint_info():
    ledger = SimpleNamespace(
        mint_info=MintInfo(
            name="Mint",
            pubkey="02" * 33,
            version="1.0",
            description="short",
            description_long="long",
            contact=[],
            motd="hello",
            icon_url="https://mint.test/icon.png",
            urls=["https://mint.test"],
            tos_url="https://mint.test/tos",
            time=None,
            nuts={4: {"supported": True}},
        )
    )
    rpc = _rpc_with_ledger(ledger)
    response = rpc.GetInfo(SimpleNamespace(), None)
    assert response.name == "Mint"
    assert response.long_description == "long"
    assert not hasattr(response, "nuts")


@pytest.mark.asyncio
async def test_update_metadata_and_contacts(monkeypatch):
    test_url = "https://rpc-test-url.example"
    test_contact = ["rpc-test-contact", "hi@test"]
    original_urls = settings.mint_info_urls
    original_contact = settings.mint_info_contact.copy()
    original_name = settings.mint_info_name
    original_motd = settings.mint_info_motd
    rpc = _rpc_with_ledger()
    try:
        filtered_urls = [u for u in (original_urls or []) if u != test_url]
        settings.mint_info_urls = filtered_urls or None
        settings.mint_info_contact = [
            contact for contact in original_contact if contact != test_contact
        ]
        await rpc.UpdateMotd(SimpleNamespace(motd="new motd"), None)
        await rpc.UpdateName(SimpleNamespace(name="New Name"), None)
        await rpc.AddUrl(SimpleNamespace(url=test_url), None)
        await rpc.AddContact(
            SimpleNamespace(method=test_contact[0], info=test_contact[1]), None
        )

        assert settings.mint_info_motd == "new motd"
        assert settings.mint_info_name == "New Name"
        assert test_url in (settings.mint_info_urls or [])
        assert test_contact in settings.mint_info_contact

        await rpc.RemoveUrl(SimpleNamespace(url=test_url), None)
        await rpc.RemoveContact(SimpleNamespace(method=test_contact[0]), None)

        assert test_url not in (settings.mint_info_urls or [])
        assert test_contact not in settings.mint_info_contact
    finally:
        settings.mint_info_urls = original_urls
        settings.mint_info_contact = original_contact
        settings.mint_info_name = original_name
        settings.mint_info_motd = original_motd


@pytest.mark.asyncio
async def test_get_and_update_quote_rpcs():
    mint_quote = MintQuote(
        quote="quote-1",
        method="bolt11",
        request="lnbc1",
        checking_id="check",
        unit="sat",
        amount=1,
        state=MintQuoteState.unpaid,
    )
    melt_quote = MeltQuote(
        quote="melt-1",
        method="bolt11",
        request="lnbc1",
        checking_id="check",
        unit="sat",
        amount=1,
        fee_reserve=1,
        state=MeltQuoteState.unpaid,
    )
    updates = []

    async def get_mint_quote(quote_id):
        return mint_quote

    async def get_melt_quote(quote_id):
        return melt_quote

    class DbWrite:
        async def _update_mint_quote_state(self, quote_id, state):
            updates.append((quote_id, state))

        async def _update_melt_quote_state(self, quote_id, state):
            updates.append((quote_id, state))

    ledger = SimpleNamespace(
        mint_info=MintInfo(
            name="Mint",
            pubkey=None,
            version="1.0",
            description="d",
            description_long="long",
            contact=[],
            motd="motd",
            icon_url=None,
            urls=None,
            tos_url=None,
            time=None,
            nuts={},
        ),
        get_mint_quote=get_mint_quote,
        get_melt_quote=get_melt_quote,
        db_write=DbWrite(),
    )
    rpc = _rpc_with_ledger(ledger)

    get_mint = await rpc.GetNut04Quote(SimpleNamespace(quote_id="quote-1"), None)
    get_melt = await rpc.GetNut05Quote(SimpleNamespace(quote_id="melt-1"), None)
    assert get_mint.quote.quote == "quote-1"
    assert get_mint.quote.state == MintQuoteState.unpaid.name
    assert get_melt.quote.quote == "melt-1"
    assert get_melt.quote.state == MeltQuoteState.unpaid.name

    await rpc.UpdateNut04Quote(SimpleNamespace(quote_id="quote-1", state="PAID"), None)
    await rpc.UpdateNut05Quote(SimpleNamespace(quote_id="melt-1", state="PAID"), None)
    assert updates == [
        ("quote-1", MintQuoteState.paid),
        ("melt-1", MeltQuoteState.paid),
    ]


@pytest.mark.asyncio
async def test_rotate_next_keyset_and_limit_updates():
    keyset = SimpleNamespace(
        id="keyset-1",
        unit=Unit.sat,
        amounts=[1, 2, 4, 8],
        input_fee_ppk=2,
        final_expiry=456,
    )

    async def rotate_next_keyset(unit, input_fee_ppk, final_expiry):
        assert unit == Unit.sat
        assert input_fee_ppk == 2
        assert final_expiry == 456
        return keyset

    ledger = SimpleNamespace(
        mint_info=MintInfo(
            name="Mint",
            pubkey=None,
            version="1.0",
            description="d",
            description_long="long",
            contact=[],
            motd="motd",
            icon_url=None,
            urls=None,
            tos_url=None,
            time=None,
            nuts={},
        ),
        rotate_next_keyset=rotate_next_keyset,
    )
    rpc = _rpc_with_ledger(ledger)

    response = await rpc.RotateNextKeyset(
        SimpleNamespace(unit="sat", input_fee_ppk=2, final_expiry=456, max_order=10),
        None,
    )
    assert response.id == "keyset-1"
    assert response.max_order == 4

    old_fee_percent = settings.lightning_fee_percent
    old_fee_min = settings.lightning_reserve_fee_min
    old_auth_rate = settings.mint_auth_rate_limit_per_minute
    old_auth_max = settings.mint_auth_max_blind_tokens
    try:
        await rpc.UpdateLightningFee(
            SimpleNamespace(fee_percent=2.5, fee_min_reserve=0), None
        )
        await rpc.UpdateAuthLimits(
            SimpleNamespace(auth_rate_limit_per_minute=60, auth_max_blind_tokens=0),
            None,
        )
        assert settings.lightning_fee_percent == 2.5
        assert settings.mint_auth_rate_limit_per_minute == 60

        with pytest.raises(Exception, match="No fee specified"):
            await rpc.UpdateLightningFee(
                SimpleNamespace(fee_percent=0, fee_min_reserve=0), None
            )
        with pytest.raises(Exception, match="No auth limit was specified"):
            await rpc.UpdateAuthLimits(
                SimpleNamespace(auth_rate_limit_per_minute=0, auth_max_blind_tokens=0),
                None,
            )
    finally:
        settings.lightning_fee_percent = old_fee_percent
        settings.lightning_reserve_fee_min = old_fee_min
        settings.mint_auth_rate_limit_per_minute = old_auth_rate
        settings.mint_auth_max_blind_tokens = old_auth_max


@pytest.mark.asyncio
async def test_serve_uses_insecure_server(monkeypatch):
    calls = {"insecure": None, "started": False}

    class FakeServer:
        def add_insecure_port(self, addr):
            calls["insecure"] = addr

        async def start(self):
            calls["started"] = True

    monkeypatch.setattr(settings, "mint_rpc_server_enable", True)
    monkeypatch.setattr(settings, "mint_rpc_server_mutual_tls", False)
    monkeypatch.setattr(settings, "mint_rpc_server_addr", "127.0.0.1")
    monkeypatch.setattr(settings, "mint_rpc_server_port", 3339)
    monkeypatch.setattr(
        "cashu.mint.management_rpc.management_rpc.grpc.aio.server", lambda: FakeServer()
    )
    monkeypatch.setattr(
        "cashu.mint.management_rpc.management_rpc.management_pb2_grpc.add_MintServicer_to_server",
        lambda servicer, server: None,
    )

    server = await rpc_module.serve(
        cast(
            Any,
            SimpleNamespace(
                mint_info=MintInfo(
                    name="Mint",
                    pubkey=None,
                    version="1.0",
                    description="d",
                    description_long="long",
                    contact=[],
                    motd="motd",
                    icon_url=None,
                    urls=None,
                    tos_url=None,
                    time=None,
                    nuts={},
                ),
            ),
        )
    )
    assert calls["insecure"] == "127.0.0.1:3339"
    assert calls["started"] is True
    assert server is not None


@pytest.mark.asyncio
async def test_serve_rejects_missing_mtls_files(monkeypatch):
    monkeypatch.setattr(settings, "mint_rpc_server_mutual_tls", True)
    monkeypatch.setattr(settings, "mint_rpc_server_key", "/missing/key.pem")
    monkeypatch.setattr(settings, "mint_rpc_server_ca", "/missing/ca.pem")
    monkeypatch.setattr(settings, "mint_rpc_server_cert", "/missing/cert.pem")
    monkeypatch.setattr(settings, "mint_rpc_server_addr", "127.0.0.1")
    monkeypatch.setattr(settings, "mint_rpc_server_port", 3339)
    monkeypatch.setattr(
        "cashu.mint.management_rpc.management_rpc.grpc.aio.server",
        lambda: SimpleNamespace(),
    )
    monkeypatch.setattr(
        "cashu.mint.management_rpc.management_rpc.management_pb2_grpc.add_MintServicer_to_server",
        lambda servicer, server: None,
    )
    monkeypatch.setattr(
        "cashu.mint.management_rpc.management_rpc.os.path.exists", lambda path: False
    )

    with pytest.raises(FileNotFoundError, match="mTLS files are missing"):
        await rpc_module.serve(
            cast(
                Any,
                SimpleNamespace(
                    mint_info=MintInfo(
                        name="Mint",
                        pubkey=None,
                        version="1.0",
                        description="d",
                        description_long="long",
                        contact=[],
                        motd="motd",
                        icon_url=None,
                        urls=None,
                        tos_url=None,
                        time=None,
                        nuts={},
                    ),
                ),
            )
        )


@pytest.mark.asyncio
async def test_shutdown_calls_server_stop():
    calls = {"grace": None}

    class FakeServer:
        async def stop(self, grace):
            calls["grace"] = grace

    await rpc_module.shutdown(FakeServer())
    assert calls["grace"] == 2
