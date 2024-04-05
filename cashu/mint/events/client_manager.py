import json
from typing import List, Union

from fastapi import WebSocket
from loguru import logger

from ...core.json_rpc.base import (
    JSONRPCError,
    JSONRPCErrorCode,
    JSONRPCErrorResponse,
    JSONRPCMethods,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCStatus,
    JSONRPCSubscribeParams,
    JSONRPCUnubscribeParams,
    JSONRRPCSubscribeResponse,
)


class LedgerEventClientManager:
    websocket: WebSocket
    subscriptions: dict[str, List[str]] = {}  # filter -> List[subId]
    max_subscriptions = 100

    def __init__(self, websocket: WebSocket):
        self.websocket = websocket

    async def start(self):
        await self.websocket.accept()
        while True:
            json_data = await self.websocket.receive_text()

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

            # check if method is in the enum
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
            try:
                resp = await self._handle_request(req)
            except Exception as e:
                resp = JSONRPCErrorResponse(
                    error=JSONRPCError(
                        code=JSONRPCErrorCode.INTERNAL_ERROR,
                        message=f"Error: {e}",
                    ),
                    id=req.id,
                )
            await self._send_msg(resp)

    async def _handle_request(self, data: JSONRPCRequest) -> JSONRPCResponse:
        logger.info(f"Received message: {data}")
        if data.method == JSONRPCMethods.SUBSCRIBE.value:
            params = JSONRPCSubscribeParams.parse_obj(data.params)
            self.add_subscription(params.filters, params.subId)
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=params.subId,
            )
            return JSONRPCResponse(result=result.dict(), id=data.id)
        elif data.method == JSONRPCMethods.UNSUBSCRIBE.value:
            params = JSONRPCUnubscribeParams.parse_obj(data.params)
            self.remove_subscription(params.subId)
            result = JSONRRPCSubscribeResponse(
                status=JSONRPCStatus.OK,
                subId=params.subId,
            )
            return JSONRPCResponse(result=result.dict(), id=data.id)
        else:
            raise ValueError(f"Invalid method: {data.method}")

    async def _send_obj(self, data: dict, subId: str):
        logger.info(f"Sending object: {data}")
        method = JSONRPCMethods.SUBSCRIBE.value
        data.update({"subId": subId})
        params = data
        resp = JSONRPCNotification(
            method=method,
            params=params,
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
            self.subscriptions[filter].append(subId)

    def remove_subscription(self, subId: str) -> None:
        for filter, subs in self.subscriptions.items():
            for sub in subs:
                if sub == subId:
                    self.subscriptions[filter].remove(sub)
                    return
        raise ValueError(f"Subscription not found: {subId}")
