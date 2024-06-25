import asyncio
import json
from typing import List, Union

from fastapi import WebSocket
from loguru import logger

from ...core.base import MeltQuote, MintQuote, ProofState
from ...core.db import Database
from ...core.json_rpc.base import (
    JSONRPCError,
    JSONRPCErrorCode,
    JSONRPCErrorResponse,
    JSONRPCMethods,
    JSONRPCNotficationParams,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCStatus,
    JSONRPCSubscribeParams,
    JSONRPCSubscriptionKinds,
    JSONRPCUnsubscribeParams,
    JSONRRPCSubscribeResponse,
)
from ...core.models import PostMeltQuoteResponse, PostMintQuoteResponse
from ...core.settings import settings
from ..crud import LedgerCrud
from ..db.read import DbReadHelper
from ..limit import limit_websocket
from .event_model import LedgerEvent


class LedgerEventClientManager:
    websocket: WebSocket
    subscriptions: dict[
        JSONRPCSubscriptionKinds, dict[str, List[str]]
    ] = {}  # [kind, [filter, List[subId]]]
    max_subscriptions = 1000
    db_read: DbReadHelper

    def __init__(self, websocket: WebSocket, db: Database, crud: LedgerCrud):
        self.websocket = websocket
        self.subscriptions = {}
        self.db_read = DbReadHelper(db, crud)

    async def start(self):
        await self.websocket.accept()

        while True:
            message = await asyncio.wait_for(
                self.websocket.receive(),
                timeout=settings.mint_websocket_read_timeout,
            )
            message_text = message.get("text")

            # Check the rate limit
            try:
                limit_websocket(self.websocket)
            except Exception as e:
                logger.error(f"Error: {e}")
                err = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.SERVER_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(err)
                continue

            # Check if message contains text
            if not message_text:
                continue

            # Parse the JSON data
            try:
                data = json.loads(message_text)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON: {e}")
                err = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.PARSE_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(err)
                continue

            # Parse the JSONRPCRequest
            try:
                req = JSONRPCRequest.parse_obj(data)
            except Exception as e:
                err = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.INVALID_REQUEST,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(err)
                logger.warning(f"Error handling websocket message: {e}")
                continue

            # Check if the method is valid
            try:
                JSONRPCMethods(req.method)
            except ValueError:
                err = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.METHOD_NOT_FOUND,
                        message=f"Method not found: {req.method}",
                    ),
                    id=req.id,
                )
                await self._send_msg(err)
                continue

            # Handle the request
            try:
                logger.debug(f"Request: {req.json()}")
                resp = await self._handle_request(req)
                # Send the response
                await self._send_msg(resp)
            except Exception as e:
                err = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.INTERNAL_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=req.id,
                )
                await self._send_msg(err)
                continue

    async def _handle_request(self, data: JSONRPCRequest) -> JSONRPCResponse:
        logger.debug(f"Received websocket message: {data}")
        if data.method == JSONRPCMethods.SUBSCRIBE.value:
            subscribe_params = JSONRPCSubscribeParams.parse_obj(data.params)
            self.add_subscription(
                subscribe_params.kind, subscribe_params.filters, subscribe_params.subId
            )
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=subscribe_params.subId,
            )
            return JSONRPCResponse(result=result.dict(), id=data.id)
        elif data.method == JSONRPCMethods.UNSUBSCRIBE.value:
            unsubscribe_params = JSONRPCUnsubscribeParams.parse_obj(data.params)
            self.remove_subscription(unsubscribe_params.subId)
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=unsubscribe_params.subId,
            )
            return JSONRPCResponse(result=result.dict(), id=data.id)
        else:
            raise ValueError(f"Invalid method: {data.method}")

    async def _send_obj(self, data: dict, subId: str):
        resp = JSONRPCNotification(
            method=JSONRPCMethods.SUBSCRIBE.value,
            params=JSONRPCNotficationParams(subId=subId, payload=data).dict(),
        )
        await self._send_msg(resp)

    async def _send_msg(
        self, data: Union[JSONRPCResponse, JSONRPCNotification, JSONRPCErrorResponse]
    ):
        logger.debug(f"Sending websocket message: {data.json()}")
        await self.websocket.send_text(data.json())

    def add_subscription(
        self,
        kind: JSONRPCSubscriptionKinds,
        filters: List[str],
        subId: str,
    ) -> None:
        if kind not in self.subscriptions:
            self.subscriptions[kind] = {}

        if len(self.subscriptions[kind]) >= self.max_subscriptions:
            raise ValueError("Max subscriptions reached")

        for filter in filters:
            if filter not in self.subscriptions:
                self.subscriptions[kind][filter] = []
            logger.debug(f"Adding subscription {subId} for filter {filter}")
            self.subscriptions[kind][filter].append(subId)
            # Initialize the subscription
            asyncio.create_task(self._init_subscription(subId, filter, kind))

    def remove_subscription(self, subId: str) -> None:
        for kind, sub_filters in self.subscriptions.items():
            for filter, subs in sub_filters.items():
                for sub in subs:
                    if sub == subId:
                        logger.debug(
                            f"Removing subscription {subId} for filter {filter}"
                        )
                        self.subscriptions[kind][filter].remove(sub)
                        return
        raise ValueError(f"Subscription not found: {subId}")

    def serialize_event(self, event: LedgerEvent) -> dict:
        if isinstance(event, MintQuote):
            return_dict = PostMintQuoteResponse.parse_obj(event.dict()).dict()
        elif isinstance(event, MeltQuote):
            return_dict = PostMeltQuoteResponse.parse_obj(event.dict()).dict()
        elif isinstance(event, ProofState):
            return_dict = event.dict(exclude_unset=True, exclude_none=True)
        return return_dict

    async def _init_subscription(
        self, subId: str, filter: str, kind: JSONRPCSubscriptionKinds
    ):
        if kind == JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE:
            mint_quote = await self.db_read.crud.get_mint_quote(
                quote_id=filter, db=self.db_read.db
            )
            if mint_quote:
                await self._send_obj(mint_quote.dict(), subId)
        elif kind == JSONRPCSubscriptionKinds.BOLT11_MELT_QUOTE:
            melt_quote = await self.db_read.crud.get_melt_quote(
                quote_id=filter, db=self.db_read.db
            )
            if melt_quote:
                await self._send_obj(melt_quote.dict(), subId)
        elif kind == JSONRPCSubscriptionKinds.PROOF_STATE:
            proofs = await self.db_read.get_proofs_states(Ys=[filter])
            if len(proofs):
                await self._send_obj(proofs[0].dict(), subId)
