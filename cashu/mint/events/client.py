import asyncio
import contextlib
import json
import time
from typing import List, Union

from fastapi import WebSocket, WebSocketDisconnect
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

        # Close connections that only subscribe to mint quotes which expire
        # unpaid, so a client cannot hold the socket open until the read timeout.
        expiry_monitor_task = asyncio.create_task(
            self._monitor_expired_mint_quote_subscriptions()
        )
        try:
            await self._receive_loop()
        finally:
            expiry_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await expiry_monitor_task

    async def _receive_loop(self):
        while True:
            message = await asyncio.wait_for(
                self.websocket.receive(),
                timeout=settings.mint_websocket_read_timeout,
            )
            if message.get("type") == "websocket.disconnect":
                raise WebSocketDisconnect(code=message.get("code", 1000))
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
                req = JSONRPCRequest.model_validate(data)
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
                logger.debug(f"Request: {req.model_dump_json()}")
                resp = await self._handle_request(req)
                # Send the response
                await self._send_msg(resp)
            except WebSocketDisconnect as e:
                logger.debug(f"Websocket disconnected: {e}")
                raise e
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
            subscribe_params = JSONRPCSubscribeParams.model_validate(data.params)
            self.add_subscription(
                subscribe_params.kind, subscribe_params.filters, subscribe_params.subId
            )
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=subscribe_params.subId,
            )
            return JSONRPCResponse(result=result.model_dump(), id=data.id)
        elif data.method == JSONRPCMethods.UNSUBSCRIBE.value:
            unsubscribe_params = JSONRPCUnsubscribeParams.model_validate(data.params)
            self.remove_subscription(unsubscribe_params.subId)
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=unsubscribe_params.subId,
            )
            return JSONRPCResponse(result=result.model_dump(), id=data.id)
        else:
            raise ValueError(f"Invalid method: {data.method}")

    async def _send_obj(self, data: dict, subId: str):
        resp = JSONRPCNotification(
            method=JSONRPCMethods.SUBSCRIBE.value,
            params=JSONRPCNotficationParams(subId=subId, payload=data).model_dump(),
        )
        await self._send_msg(resp)

    async def _send_msg(
        self, data: Union[JSONRPCResponse, JSONRPCNotification, JSONRPCErrorResponse]
    ):
        logger.debug(f"Sending websocket message: {data.model_dump_json()}")
        await self.websocket.send_text(data.model_dump_json())

    async def _monitor_expired_mint_quote_subscriptions(self) -> None:
        """Close the websocket once every subscribed bolt11 mint quote is in a
        terminal state.

        A subscription to a mint quote can only produce a finite set of state
        transitions. Once all subscribed quotes are either paid, or have expired
        while unpaid, no more useful events are expected. Proactively closing
        such connections frees server resources and reflects that the
        subscription is dead.
        """
        interval = settings.mint_websocket_quote_expiry_check_interval
        while True:
            await asyncio.sleep(interval)
            quote_filters = list(
                self.subscriptions.get(
                    JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE, {}
                )
            )
            if not quote_filters:
                continue

            now = int(time.time())
            all_terminal = True
            async with self.db_read.db.connect() as conn:
                for quote_id in quote_filters:
                    mint_quote = await self.db_read.crud.get_mint_quote(
                        quote_id=quote_id, db=self.db_read.db, conn=conn
                    )
                    # A quote is terminal when it is paid, or when it is
                    # unpaid and has passed its expiry.
                    terminal = bool(
                        mint_quote
                        and (
                            mint_quote.paid
                            or (
                                mint_quote.unpaid
                                and mint_quote.expiry
                                and mint_quote.expiry <= now
                            )
                        )
                    )
                    if not terminal:
                        all_terminal = False
                        break

            if all_terminal:
                logger.info(
                    "Closing websocket: all subscribed mint quotes are terminal"
                )
                with contextlib.suppress(Exception):
                    await self.websocket.close(
                        code=1000, reason="mint quote subscription terminal"
                    )
                return

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

        for f in filters:
            logger.debug(f"Adding subscription {subId} for filter {f}")
            self.subscriptions[kind].setdefault(f, []).append(subId)
            
        # Initialize the subscriptions in batch
        asyncio.create_task(self._init_subscriptions(subId, filters, kind))

    def remove_subscription(self, subId: str) -> None:
        removed = False
        for kind, sub_filters in self.subscriptions.items():
            for filter, subs in sub_filters.items():
                while subId in subs:
                    logger.debug(
                        f"Removing subscription {subId} for filter {filter}"
                    )
                    subs.remove(subId)
                    removed = True
        if not removed:
            raise ValueError(f"Subscription not found: {subId}")

    def serialize_event(self, event: LedgerEvent) -> dict:
        if isinstance(event, MintQuote):
            return_dict = PostMintQuoteResponse.from_mint_quote(event).model_dump()
        elif isinstance(event, MeltQuote):
            return_dict = PostMeltQuoteResponse.from_melt_quote(event).model_dump()
        elif isinstance(event, ProofState):
            return_dict = event.model_dump(exclude_unset=True, exclude_none=True)
        return return_dict

    async def _init_subscriptions(
        self, subId: str, filters: List[str], kind: JSONRPCSubscriptionKinds
    ):
        results = []
        async with self.db_read.db.connect() as conn:
            if kind == JSONRPCSubscriptionKinds.BOLT11_MINT_QUOTE:
                for filter in filters:
                    mint_quote = await self.db_read.crud.get_mint_quote(
                        quote_id=filter, db=self.db_read.db, conn=conn
                    )
                    if mint_quote:
                        results.append(PostMintQuoteResponse.from_mint_quote(mint_quote).model_dump())
            elif kind == JSONRPCSubscriptionKinds.BOLT11_MELT_QUOTE:
                for filter in filters:
                    melt_quote = await self.db_read.crud.get_melt_quote(
                        quote_id=filter, db=self.db_read.db, conn=conn
                    )
                    if melt_quote:
                        results.append(PostMeltQuoteResponse.from_melt_quote(melt_quote).model_dump())
            elif kind == JSONRPCSubscriptionKinds.PROOF_STATE:
                proofs = await self.db_read.get_proofs_states(Ys=filters, conn=conn)
                for proof in proofs:
                    results.append(proof.model_dump())
        
        for result in results:
            await self._send_obj(result, subId)
