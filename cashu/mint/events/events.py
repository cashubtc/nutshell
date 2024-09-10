import asyncio

from fastapi import WebSocket
from loguru import logger

from ...core.base import MeltQuote, MintQuote, ProofState
from ...core.db import Database
from ...core.models import PostMeltQuoteResponse, PostMintQuoteResponse
from ..crud import LedgerCrud
from .client import LedgerEventClientManager
from .event_model import LedgerEvent


class LedgerEventManager:
    """LedgerEventManager is a subscription service from the mint
    for client websockets that subscribe to event updates.

    Yields:
        _type_: Union[MintQuote, MeltQuote]
    """

    clients: list[LedgerEventClientManager] = []

    MAX_CLIENTS = 1000

    def add_client(
        self, websocket: WebSocket, db: Database, crud: LedgerCrud
    ) -> LedgerEventClientManager:
        client = LedgerEventClientManager(websocket, db, crud)
        if len(self.clients) >= self.MAX_CLIENTS:
            raise Exception("too many clients")
        self.clients.append(client)
        logger.debug(f"Added websocket subscription client {client}")
        return client

    def remove_client(self, client: LedgerEventClientManager) -> None:
        self.clients.remove(client)

    def serialize_event(self, event: LedgerEvent) -> dict:
        if isinstance(event, MintQuote):
            return_dict = PostMintQuoteResponse.from_mint_quote(event).dict()
        elif isinstance(event, MeltQuote):
            return_dict = PostMeltQuoteResponse.from_melt_quote(event).dict()
        elif isinstance(event, ProofState):
            return_dict = event.dict(exclude_unset=True, exclude_none=True)
        return return_dict

    async def submit(self, event: LedgerEvent) -> None:
        if not isinstance(event, LedgerEvent):
            raise ValueError(f"Unsupported event object type {type(event)}")

        # check if any clients are subscribed to this event
        for client in self.clients:
            kind_sub = client.subscriptions.get(event.kind, {})
            for sub in kind_sub.get(event.identifier, []):
                logger.trace(
                    f"Submitting event to sub {sub}: {self.serialize_event(event)}"
                )
                asyncio.create_task(
                    client._send_obj(self.serialize_event(event), subId=sub)
                )
