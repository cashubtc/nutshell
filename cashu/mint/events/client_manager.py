import json
from typing import List, Union

from fastapi import WebSocket
from loguru import logger

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
from ..limit import limit_websocket


class LedgerEventClientManager:
    websocket: WebSocket
    subscriptions: dict[
        JSONRPCSubscriptionKinds, dict[str, List[str]]
    ] = {}  # [kind, [filter, List[subId]]]
    max_subscriptions = 100

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket
        self.subscriptions = {}

    async def start(self):
        await self.websocket.accept()
        while True:
            json_data = await self.websocket.receive_text()

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

            # Parse the JSON data
            try:
                data = json.loads(json_data)
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
                logger.debug(f"Request: {req}")
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
        logger.info(f"Received message: {data}")
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
        logger.info(f"Sending object: {data}")
        resp = JSONRPCNotification(
            method=JSONRPCMethods.SUBSCRIBE.value,
            params=JSONRPCNotficationParams(subId=subId, payload=data).dict(),
        )
        await self._send_msg(resp)

    async def _send_msg(
        self, data: Union[JSONRPCResponse, JSONRPCNotification, JSONRPCErrorResponse]
    ):
        logger.info(f"Sending message: {data}")
        await self.websocket.send_text(data.json())

    def add_subscription(
        self, kind: JSONRPCSubscriptionKinds, filters: List[str], subId: str
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
            # self.handle_subscription_init(kind, filters, subId)

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
