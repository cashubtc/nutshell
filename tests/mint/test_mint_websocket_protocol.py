import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi import WebSocketDisconnect

from cashu.core.base import (
    MeltQuote,
    MeltQuoteState,
    MintQuote,
    MintQuoteState,
    ProofSpentState,
    ProofState,
)
from cashu.core.json_rpc.base import (
    JSONRPCErrorCode,
    JSONRPCMethods,
    JSONRPCRequest,
    JSONRPCSubscriptionKinds,
)
from cashu.mint.events.client import LedgerEventClientManager
from cashu.mint.events.events import LedgerEventManager


class FakeWebSocket:
    def __init__(self, messages: list[dict[str, Any]] | None = None):
        self.messages = messages or []
        self.sent: list[str] = []
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def receive(self):
        if self.messages:
            return self.messages.pop(0)
        raise WebSocketDisconnect(code=1000)

    async def send_text(self, data: str):
        self.sent.append(data)


def _client_manager(websocket: FakeWebSocket) -> LedgerEventClientManager:
    manager = LedgerEventClientManager(
        cast(Any, websocket), cast(Any, object()), cast(Any, object())
    )
    manager.db_read = cast(
        Any,
        SimpleNamespace(
            db=object(),
            crud=SimpleNamespace(get_mint_quote=None, get_melt_quote=None),
            get_proofs_states=None,
        ),
    )
    return manager


@pytest.mark.asyncio
async def test_websocket_start_returns_jsonrpc_errors(monkeypatch):
    messages = [
        {"text": "{"},
        {"text": json.dumps({"foo": "bar"})},
        {
            "text": json.dumps(
                {"jsonrpc": "2.0", "id": 1, "method": "nope", "params": {}}
            )
        },
        {
            "text": json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": JSONRPCMethods.UNSUBSCRIBE.value,
                    "params": {"subId": "missing"},
                }
            )
        },
    ]
    websocket = FakeWebSocket(messages)
    manager = _client_manager(websocket)
    monkeypatch.setattr("cashu.mint.events.client.limit_websocket", lambda ws: None)

    with pytest.raises(WebSocketDisconnect):
        await manager.start()

    assert websocket.accepted is True
    parsed = [json.loads(msg) for msg in websocket.sent]
    assert parsed[0]["error"]["code"] == JSONRPCErrorCode.PARSE_ERROR.value
    assert parsed[1]["error"]["code"] == JSONRPCErrorCode.INVALID_REQUEST.value
    assert parsed[2]["error"]["code"] == JSONRPCErrorCode.METHOD_NOT_FOUND.value
    assert parsed[3]["error"]["code"] == JSONRPCErrorCode.INTERNAL_ERROR.value


@pytest.mark.asyncio
async def test_handle_request_subscribe_and_unsubscribe_roundtrip(monkeypatch):
    manager = _client_manager(FakeWebSocket())
    monkeypatch.setattr(
        "cashu.mint.events.client.asyncio.create_task",
        lambda coro: (coro.close(), None)[1],
    )
    req = JSONRPCRequest(
        id=1,
        method=JSONRPCMethods.SUBSCRIBE.value,
        params={
            "kind": JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE.value,
            "filters": ["quote-1"],
            "subId": "sub-1",
        },
    )
    resp = await manager._handle_request(req)
    assert resp.result["subId"] == "sub-1"
    assert manager.subscriptions[JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE][
        "quote-1"
    ] == ["sub-1"]

    req_unsub = JSONRPCRequest(
        id=2,
        method=JSONRPCMethods.UNSUBSCRIBE.value,
        params={"subId": "sub-1"},
    )
    resp_unsub = await manager._handle_request(req_unsub)
    assert resp_unsub.result["subId"] == "sub-1"
    assert (
        manager.subscriptions[JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE]["quote-1"]
        == []
    )


def test_add_subscription_rejects_when_max_reached():
    manager = _client_manager(FakeWebSocket())
    manager.max_subscriptions = 0
    with pytest.raises(ValueError, match="Max subscriptions reached"):
        manager.add_subscription(JSONRPCSubscriptionKinds.PROOF_STATE, ["Y1"], "sub-1")


@pytest.mark.asyncio
async def test_init_subscription_sends_initial_snapshots():
    websocket = FakeWebSocket()
    manager = _client_manager(websocket)

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
    proof_state = ProofState(Y="Y1", state=ProofSpentState.unspent)

    manager.db_read = cast(
        Any,
        SimpleNamespace(
            db=object(),
            crud=SimpleNamespace(
                get_mint_quote=None,
                get_melt_quote=None,
            ),
            get_proofs_states=None,
        ),
    )

    async def get_mint_quote(quote_id, db):
        return mint_quote if quote_id == "quote-1" else None

    async def get_melt_quote(quote_id, db):
        return melt_quote if quote_id == "melt-1" else None

    async def get_proofs_states(Ys):
        return [proof_state]

    cast(Any, manager.db_read).crud.get_mint_quote = get_mint_quote
    cast(Any, manager.db_read).crud.get_melt_quote = get_melt_quote
    cast(Any, manager.db_read).get_proofs_states = get_proofs_states

    async def send_obj(data: dict, subId: str):
        websocket.sent.append(
            json.dumps({"subId": subId, "payload": data}, default=str)
        )

    cast(Any, manager)._send_obj = send_obj

    await manager._init_subscriptions(
        "sub-mint", ["quote-1"], JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE
    )
    await manager._init_subscriptions(
        "sub-melt", ["melt-1"], JSONRPCSubscriptionKinds.BOLT11_MELT_QUOTE
    )
    await manager._init_subscriptions(
        "sub-proof", ["Y1"], JSONRPCSubscriptionKinds.PROOF_STATE
    )

    payloads = [json.loads(msg) for msg in websocket.sent]
    assert payloads[0]["payload"]["quote"] == "quote-1"
    assert payloads[1]["payload"]["quote"] == "melt-1"
    assert payloads[2]["payload"]["Y"] == "Y1"


@pytest.mark.asyncio
async def test_event_manager_submits_only_to_matching_subscribers(monkeypatch):
    sent: list[tuple[str, dict]] = []

    class FakeClient:
        def __init__(self, subscriptions):
            self.subscriptions = subscriptions

        async def _send_obj(self, data: dict, subId: str):
            sent.append((subId, data))

    manager = LedgerEventManager()
    manager.clients = cast(
        Any,
        [
            FakeClient(
                {JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE: {"quote-1": ["sub-1"]}}
            ),
            FakeClient(
                {JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE: {"quote-2": ["sub-2"]}}
            ),
        ],
    )

    created = []

    def fake_create_task(coro):
        created.append(coro)
        return cast(Any, coro)

    monkeypatch.setattr(
        "cashu.mint.events.events.asyncio.create_task", fake_create_task
    )

    event = MintQuote(
        quote="quote-1",
        method="bolt11",
        request="lnbc1",
        checking_id="check",
        unit="sat",
        amount=1,
        state=MintQuoteState.paid,
    )
    await manager.submit(event)

    assert len(created) == 1
    await created[0]
    assert sent[0][0] == "sub-1"
    assert sent[0][1]["quote"] == "quote-1"


@pytest.mark.asyncio
async def test_event_manager_rejects_unsupported_events():
    manager = LedgerEventManager()
    with pytest.raises(ValueError, match="Unsupported event object type"):
        await manager.submit(cast(Any, object()))
