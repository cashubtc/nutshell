import asyncio
import base64
import json
from contextlib import suppress
from types import SimpleNamespace
from typing import Any, cast
from urllib.parse import parse_qs

import httpx
import pytest
from loguru import logger

from cashu.core.base import Unit
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.lightning.clnrest import CLNRestWallet
from cashu.lightning.http import STREAM_READ_TIMEOUT, http_timeout
from cashu.lightning.lndrest import LndRestWallet
from cashu.lightning.strike import StrikeWallet
from tests.lightning.test_lightning_backends_mocked import _quote

TEST_READ_TIMEOUT_SECONDS = 0.05
TEST_STREAM_WAIT_TIMEOUT_SECONDS = 2.0


@pytest.fixture
def error_logs():
    messages = []
    sink_id = logger.add(messages.append, level="ERROR")
    yield messages
    logger.remove(sink_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", [CLNRestWallet, LndRestWallet, StrikeWallet])
async def test_http_backends_have_no_default_timeouts(monkeypatch, backend):
    """Only paid invoice streams get a timeout; melts and other requests must not
    time out, since a timeout could be mistaken for a failed payment."""
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
        assert isinstance(timeout, httpx.Timeout)
        assert all(
            value is None
            for value in (timeout.connect, timeout.read, timeout.write, timeout.pool)
        )
    finally:
        await wallet.client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", [CLNRestWallet, LndRestWallet])
@pytest.mark.parametrize("idle_before_response", [False, True])
async def test_invoice_stream_reconnects_after_read_timeout(
    monkeypatch, backend, idle_before_response, error_logs
):
    """A real HTTP stream stalls, reconnects, and delivers a new payment."""
    subscriptions = 0
    cursors = []
    handlers = set()
    writers = set()
    first_hash, second_hash = "11" * 32, "22" * 32

    async def serve(reader, writer):
        nonlocal subscriptions
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
            subscriptions += 1
            if idle_before_response and subscriptions == 1:
                await reader.read()
                return
            index = 7 + subscriptions - int(idle_before_response)
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

    def stream_timeout(read):
        # the paid invoice stream is the only call site of http_timeout
        assert read == STREAM_READ_TIMEOUT
        return http_timeout(TEST_READ_TIMEOUT_SECONDS)

    monkeypatch.setattr(f"{backend.__module__}.http_timeout", stream_timeout)
    stream = wallet.paid_invoices_stream()
    try:
        assert (
            await asyncio.wait_for(stream.__anext__(), TEST_STREAM_WAIT_TIMEOUT_SECONDS)
            == first_hash
        )
        assert (
            await asyncio.wait_for(stream.__anext__(), TEST_STREAM_WAIT_TIMEOUT_SECONDS)
            == second_hash
        )
        assert subscriptions == (3 if idle_before_response else 2)
        if backend is CLNRestWallet:
            assert cursors == ([7, 7, 8] if idle_before_response else [7, 8])
        assert not error_logs
    finally:
        await stream.aclose()
        await client.aclose()
        server.close()
        await server.wait_closed()
        for writer in list(writers):
            writer.close()
        await asyncio.gather(*handlers, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("backend", [CLNRestWallet, LndRestWallet])
@pytest.mark.parametrize(
    "error",
    [httpx.ConnectError, httpx.ConnectTimeout, httpx.WriteTimeout, httpx.PoolTimeout],
)
async def test_invoice_stream_logs_errors_and_retries(
    monkeypatch, backend, error, error_logs
):
    attempts = 0
    delays = []
    payment_hash = "11" * 32
    event = (
        {"status": "paid", "pay_index": 1, "payment_hash": payment_hash}
        if backend is CLNRestWallet
        else {
            "result": {
                "settled": True,
                "r_hash": base64.b64encode(bytes.fromhex(payment_hash)).decode(),
            }
        }
    )

    async def respond(request):
        nonlocal attempts
        if request.url.path == "/v1/listinvoices":
            return httpx.Response(200, json={"invoices": []})
        attempts += 1
        if attempts <= 2:
            raise error("backend unavailable", request=request)
        return httpx.Response(200, json=event)

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(f"{backend.__module__}.asyncio", SimpleNamespace(sleep=sleep))
    wallet = object.__new__(backend)
    wallet.unit = Unit.sat
    async with httpx.AsyncClient(
        base_url="http://backend.test", transport=httpx.MockTransport(respond)
    ) as client:
        cast(Any, wallet).client = client
        stream = wallet.paid_invoices_stream()
        try:
            assert (
                await asyncio.wait_for(
                    stream.__anext__(), TEST_STREAM_WAIT_TIMEOUT_SECONDS
                )
                == payment_hash
            )
        finally:
            await stream.aclose()

    assert attempts == 3
    assert delays == [0, settings.mint_retry_exponential_backoff_base_delay]
    assert len(error_logs) == 2
    assert all("backend unavailable" in message for message in error_logs)


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
