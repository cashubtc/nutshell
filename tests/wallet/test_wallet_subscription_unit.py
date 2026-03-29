import json
from typing import Any, cast

from cashu.core.json_rpc.base import (
    JSONRPCMethods,
    JSONRPCNotficationParams,
    JSONRPCNotification,
    JSONRPCResponse,
    JSONRPCSubscriptionKinds,
)
from cashu.wallet.subscriptions import SubscriptionManager


class FakeWebSocketApp:
    def __init__(self, url, on_message=None):
        self.url = url
        self.on_message = on_message
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


def test_subscription_manager_builds_websocket_url(monkeypatch):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)

    http_mgr = SubscriptionManager("http://mint.test")
    https_mgr = SubscriptionManager("https://mint.test:444")

    assert http_mgr.url == "ws://mint.test/v1/ws"
    assert https_mgr.url == "wss://mint.test:444/v1/ws"


def test_subscription_manager_subscribe_and_close(monkeypatch):
    monkeypatch.setattr("cashu.wallet.subscriptions.WebSocketApp", FakeWebSocketApp)
    monkeypatch.setattr("cashu.wallet.subscriptions.random_hash", lambda: "sub-1")
    manager = SubscriptionManager("https://mint.test")
    monkeypatch.setattr(manager, "wait_until_connected", lambda: None)

    calls = []

    def callback(params):
        calls.append(params)

    manager.subscribe(JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE, ["quote-1"], callback)
    assert manager.id_counter == 1
    assert "sub-1" in manager.callback_map

    sent = json.loads(cast(Any, manager).websocket.sent[0])
    assert sent["method"] == JSONRPCMethods.SUBSCRIBE.value
    assert sent["params"]["subId"] == "sub-1"

    manager.close()
    unsubscribe_messages = [
        json.loads(message)
        for message in cast(Any, manager).websocket.sent[1:]
        if json.loads(message)["method"] == JSONRPCMethods.UNSUBSCRIBE.value
    ]
    assert any(msg["params"]["subId"] == "sub-1" for msg in unsubscribe_messages)
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
