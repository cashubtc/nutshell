import json
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from cashu.core.base import AuthProof, Proof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.json_rpc.base import (
    JSONRPCMethods,
    JSONRPCNotficationParams,
    JSONRPCNotification,
    JSONRPCResponse,
    JSONRPCSubscriptionKinds,
)
from cashu.core.nuts import nut22
from cashu.wallet.subscriptions import SubscriptionManager
from cashu.wallet.wallet import Wallet


class FakeWebSocketApp:
    def __init__(self, url, on_message=None, header=None):
        self.url = url
        self.on_message = on_message
        self.headers = header
        self.sent: list[str] = []
        self.keep_running = True
        self.sock = type("Sock", (), {"connected": True})()
        self.closed = False

    def send(self, data: str):
        self.sent.append(data)

    def close(self):
        self.closed = True

    def run_forever(self, ping_interval=10, ping_timeout=5):
        return None


@pytest.mark.asyncio
async def test_wallet_signs_a_bat_for_the_websocket_upgrade(monkeypatch):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)
    key = PrivateKey((3).to_bytes(32, "big"))
    proof = Proof(id="02" + "ab" * 32, amount=1, secret=key.public_key.format().hex(), C="aa" * 48, derivation_path=nut22.BATKEY_PREFIX + key.to_hex())
    monkeypatch.setattr("cashu.wallet.wallet.get_proofs", AsyncMock(return_value=[proof]))
    invalidate = AsyncMock()
    monkeypatch.setattr("cashu.wallet.wallet.invalidate_proof", invalidate)
    wallet = Wallet.__new__(Wallet)
    wallet.url = "https://mint.test/cashu"
    wallet.mint_info = SimpleNamespace(requires_blind_auth_path=lambda method, path: method == "GET" and path == "/v1/ws")
    wallet.auth_db, wallet.auth_keyset_id = object(), proof.id
    manager = await wallet._subscription_manager()
    presented = AuthProof.from_base64(manager.websocket.headers["Blind-auth"])
    assert manager.url == "wss://mint.test/cashu/v1/ws"
    assert nut22.verify_bat_request_witness(presented, "GET", "/v1/ws", b"")
    assert not nut22.verify_bat_request_witness(presented, "POST", "/v1/ws", b"")
    invalidate.assert_awaited_once_with(proof=proof, db=wallet.auth_db)


def test_subscription_manager_builds_websocket_url(monkeypatch):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)

    http_mgr = SubscriptionManager("http://mint.test")
    https_mgr = SubscriptionManager("https://mint.test:444")

    assert http_mgr.url == "ws://mint.test/v1/ws"
    assert https_mgr.url == "wss://mint.test:444/v1/ws"
    protected = SubscriptionManager("https://mint.test:444/cashu", headers={"Blind-auth": "authAexample"})
    assert protected.url == "wss://mint.test:444/cashu/v1/ws"
    assert protected.websocket.headers == {"Blind-auth": "authAexample"}


def test_subscription_manager_subscribe_and_close(monkeypatch):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)
    monkeypatch.setattr(
        "cashu.wallet.subscriptions.generate_uuid_v7",
        lambda: "018f0f61-8c4d-7cc2-8f21-4a6b5f0b6a11",
    )
    manager = SubscriptionManager("https://mint.test")
    monkeypatch.setattr(manager, "wait_until_connected", lambda: None)

    calls = []

    def callback(params):
        calls.append(params)

    manager.subscribe(JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE, ["quote-1"], callback)
    assert manager.id_counter == 1
    assert "018f0f61-8c4d-7cc2-8f21-4a6b5f0b6a11" in manager.callback_map

    sent = json.loads(cast(Any, manager).websocket.sent[0])
    assert sent["method"] == JSONRPCMethods.SUBSCRIBE.value
    assert sent["params"]["subId"] == "018f0f61-8c4d-7cc2-8f21-4a6b5f0b6a11"

    manager.close()
    unsubscribe_messages = [
        json.loads(message)
        for message in cast(Any, manager).websocket.sent[1:]
        if json.loads(message)["method"] == JSONRPCMethods.UNSUBSCRIBE.value
    ]
    assert any(
        msg["params"]["subId"] == "018f0f61-8c4d-7cc2-8f21-4a6b5f0b6a11"
        for msg in unsubscribe_messages
    )
    assert cast(Any, manager).websocket.closed is True


def test_subscription_manager_on_message_ignores_responses_and_dispatches_notifications(
    monkeypatch,
):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)
    manager = SubscriptionManager("https://mint.test")
    received = []
    manager.callback_map["sub-1"] = lambda params: received.append(params)

    response_message = cast(
        Any, JSONRPCResponse(result={"status": "OK"}, id=1)
    ).model_dump_json()
    manager._on_message(None, response_message)
    assert received == []

    notification = JSONRPCNotification(
        method=JSONRPCMethods.SUBSCRIBE.value,
        params=cast(
            Any, JSONRPCNotficationParams(subId="sub-1", payload={"state": "PAID"})
        ).model_dump(),
    )
    manager._on_message(None, cast(Any, notification).model_dump_json())
    assert received[0].subId == "sub-1"
    assert received[0].payload == {"state": "PAID"}

    manager._on_message(None, "not-json")
    assert len(received) == 1
