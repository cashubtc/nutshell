import json
from typing import List, Union

from fastapi import WebSocket
from loguru import logger

from cashu.mint.limit import assert_limit

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
    JSONRPCUnsubscribeParams,
    JSONRRPCSubscribeResponse,
)


class LedgerEventClientManager:
    websocket: WebSocket
    subscriptions: dict[str, List[str]] = {}  # [filter, List[subId]]
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
                assert_limit(
                    self.websocket.client.host if self.websocket.client else "unknown"
                )
            except Exception as e:
                logger.error(f"Error: {e}")
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.SERVER_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(resp)
                continue

            # Parse the JSON data
            try:
                data = json.loads(json_data)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON: {e}")
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.PARSE_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(resp)
                continue

            # Parse the JSONRPCRequest
            try:
                req = JSONRPCRequest.parse_obj(data)
            except Exception as e:
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.INVALID_REQUEST,
                        message=f"Error: {e}",
                    ),
                    id=0,
                )
                await self._send_msg(resp)
                logger.warning(f"Error handling websocket message: {e}")
                continue

            # Check if the method is valid
            try:
                JSONRPCMethods(req.method)
            except ValueError:
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.METHOD_NOT_FOUND,
                        message=f"Method not found: {req.method}",
                    ),
                    id=req.id,
                )
                await self._send_msg(resp)
                continue

            # Handle the request
            try:
                logger.debug(f"Request: {req}")
                resp = await self._handle_request(req)
            except Exception as e:
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.INTERNAL_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=req.id,
                )

            # Send the response
            await self._send_msg(resp)

    async def _handle_request(self, data: JSONRPCRequest) -> JSONRPCResponse:
        logger.info(f"Received message: {data}")
        if data.method == JSONRPCMethods.SUBSCRIBE.value:
            subscribe_params = JSONRPCSubscribeParams.parse_obj(data.params)
            self.add_subscription(subscribe_params.filters, subscribe_params.subId)
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

    def add_subscription(self, filters: List[str], subId: str) -> None:
        if len(self.subscriptions) >= self.max_subscriptions:
            raise ValueError("Max subscriptions reached")
        for filter in filters:
            if filter not in self.subscriptions:
                self.subscriptions[filter] = []
            logger.debug(f"Adding subscription {subId} for filter {filter}")
            self.subscriptions[filter].append(subId)

    def remove_subscription(self, subId: str) -> None:
        for filter, subs in self.subscriptions.items():
            for sub in subs:
                if sub == subId:
                    logger.debug(f"Removing subscription {subId} for filter {filter}")
                    self.subscriptions[filter].remove(sub)
                    return
        raise ValueError(f"Subscription not found: {subId}")