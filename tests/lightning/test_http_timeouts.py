import asyncio
import base64
import json
from contextlib import suppress
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from cashu.core.base import Unit
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.lndrest import LndRestWallet
from cashu.lightning.strike import StrikeWallet
from tests.lightning.test_lightning_backends_mocked import _quote


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", [CLNRestWallet, LndRestWallet, StrikeWallet])
async def test_http_backend_defaults_are_bounded(monkeypatch, backend):
    monkeypatch.setattr(settings, "mint_clnrest_url", "http://backend.test")
    monkeypatch.setattr(settings, "mint_clnrest_rune", "test-rune")
    monkeypatch.setattr(settings, "mint_clnrest_cert", None)
    monkeypatch.setattr(settings, "mint_lnd_rest_endpoint", "http://backend.test")
    monkeypatch.setattr(settings, "mint_lnd_rest_macaroon", "ab" * 32)
    monkeypatch.setattr(settings, "mint_lnd_rest_cert", None)
    monkeypatch.setattr(settings, "mint_lnd_rest_cert_verify", False)
    monkeypatch.setattr(settings, "mint_strike_key", "test-key")
    wallet = backend(Unit.sat)
    try:
        timeout = wallet.client.timeout
        assert all(
            value is not None and value > 0
            for value in (timeout.connect, timeout.read, timeout.write, timeout.pool)
        )
    finally:
        await wallet.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", [CLNRestWallet, LndRestWallet])
async def test_invoice_stream_recovers_from_silent_connection(monkeypatch, backend):
    """A real HTTP stream emits one payment, stalls, then resumes after timeout."""
    cursors = []
    handlers = set()
    writers = set()
    first_hash, second_hash = "11" * 32, "22" * 32

    async def serve(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        writers.add(writer)
        try:
            headers = (await reader.readuntil(b"\r\n\r\n")).decode()
            target = headers.splitlines()[0].split()[1]
            content_length = next(
                (
                    int(h.split(":", 1)[1])
                    for h in headers.splitlines()
                    if h.lower().startswith("content-length:")
                ),
                0,
            )
            body = await reader.readexactly(content_length)
            if target == "/v1/listinvoices":
                data = json.dumps(
                    {"invoices": [{"status": "paid", "pay_index": 7}]}
                ).encode()
                writer.write(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                    + str(len(data)).encode()
                    + b"\r\n\r\n"
                    + data
                )
                await writer.drain()
                return

            if backend is CLNRestWallet:
                cursors.append(int(parse_qs(body.decode())["lastpay_index"][0]))
            else:
                cursors.append(int(parse_qs(urlsplit(target).query)["settle_index"][0]))
            index = 8 if len(cursors) == 1 else 9
            payment_hash = first_hash if index == 8 else second_hash
            event = (
                {"status": "paid", "pay_index": index, "payment_hash": payment_hash}
                if backend is CLNRestWallet
                else {
                    "result": {
                        "settled": True,
                        "settle_index": str(index),
                        "r_hash": base64.b64encode(
                            bytes.fromhex(payment_hash)
                        ).decode(),
                    }
                }
            )
            writer.write(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"
                + json.dumps(event).encode()
                + b"\n"
            )
            await writer.drain()
            # Leave TCP connected with no further bytes. Only the read timeout
            # can cause a reconnect; no disconnect or server-side error occurs.
            await reader.read()
        finally:
            writers.discard(writer)
            writer.close()
            with suppress(ConnectionError):
                await writer.wait_closed()
            handlers.discard(task)

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    wallet = object.__new__(backend)
    client = httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", timeout=None)
    cast(Any, wallet).client = client
    wallet.unit = Unit.sat
    monkeypatch.setattr(
        f"{backend.__module__}.http_timeout",
        lambda read=60.0: httpx.Timeout(0.05),
        raising=False,
    )
    stream = wallet.paid_invoices_stream()
    try:
        assert await asyncio.wait_for(stream.__anext__(), 2) == first_hash
        assert await asyncio.wait_for(stream.__anext__(), 2) == second_hash
        assert cursors == ([7, 8] if backend is CLNRestWallet else [0, 8])
    finally:
        await stream.aclose()
        await client.aclose()
        server.close()
        await server.wait_closed()
        for writer in list(writers):
            writer.close()
        await asyncio.gather(*handlers, return_exceptions=True)


@pytest.mark.asyncio
async def test_strike_payment_timeout_is_uncertain():
    wallet = object.__new__(StrikeWallet)
    wallet.endpoint = "http://strike.test"

    async def timeout(request):
        raise httpx.ReadTimeout("silent connection", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(timeout)) as client:
        wallet.client = client
        result = await wallet.pay_invoice(_quote("invoice"), 1000)

    assert result.result == PaymentResult.ERROR
    assert result.checking_id == "checking-1"


@pytest.mark.asyncio
@pytest.mark.parametrize("paginated", [False, True])
async def test_lnd_recovers_first_settlement_missed_during_stall(paginated):
    subscriptions = []
    offsets = []
    recovered_hash, next_hash = "33" * 32, "44" * 32
    middle_hash = "55" * 32

    class InterruptedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            raise httpx.ReadTimeout("first settlement lost")
            yield b""  # make this an async generator

    def invoice(payment_hash, index):
        return {
            "settled": True,
            "settle_index": str(index),
            "r_hash": base64.b64encode(bytes.fromhex(payment_hash)).decode(),
        }

    async def respond(request):
        if request.url.path == "/v1/invoices":
            offset = int(request.url.params["index_offset"])
            offsets.append(offset)
            if paginated and offset == 0:
                # Add order differs from settle order across invoice pages.
                return httpx.Response(
                    200,
                    json={
                        "invoices": [{"settled": False}] * 999
                        + [invoice(middle_hash, 2)],
                        "last_index_offset": "1000",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "invoices": [invoice(recovered_hash, 1)],
                    "last_index_offset": "1",
                },
            )
        subscriptions.append(request.url.params["settle_index"])
        if len(subscriptions) == 1:
            return httpx.Response(200, stream=InterruptedStream())
        return httpx.Response(
            200,
            content=json.dumps(
                {"result": invoice(next_hash, 3 if paginated else 2)}
            ).encode()
            + b"\n",
        )

    wallet = object.__new__(LndRestWallet)
    async with httpx.AsyncClient(
        base_url="http://lnd.test", transport=httpx.MockTransport(respond)
    ) as client:
        wallet.client = client
        stream = wallet.paid_invoices_stream()
        try:
            assert await asyncio.wait_for(stream.__anext__(), 2) == recovered_hash
            if paginated:
                assert await asyncio.wait_for(stream.__anext__(), 2) == middle_hash
            assert await asyncio.wait_for(stream.__anext__(), 2) == next_hash
            assert subscriptions == ["0", "2" if paginated else "1"]
            assert offsets == ([0, 1000] if paginated else [0])
        finally:
            await stream.aclose()
