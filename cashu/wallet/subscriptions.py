import time
from typing import Callable, List
from urllib.parse import urlparse

from loguru import logger
from websocket._app import WebSocketApp

from ..core.crypto.keys import random_hash
from ..core.json_rpc.base import (
    JSONRPCMethods,
    JSONRPCNotficationParams,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
    JSONRPCSubscribeParams,
    JSONRPCSubscriptionKinds,
    JSONRPCUnsubscribeParams,
)


class SubscriptionManager:
    url: str
    websocket: WebSocketApp
    id_counter: int = 0
    callback_map: dict[str, Callable] = {}

    def __init__(self, url: str):
        # parse hostname from url with urlparse
        hostname = urlparse(url).hostname
        port = urlparse(url).port
        if port:
            hostname = f"{hostname}:{port}"
        scheme = urlparse(url).scheme
        ws_scheme = "wss" if scheme == "https" else "ws"
        ws_url = f"{ws_scheme}://{hostname}/v1/ws"
        self.url = ws_url
        self.websocket = WebSocketApp(ws_url, on_message=self._on_message)

    def _on_message(self, ws, message):
        logger.trace(f"Received message: {message}")
        try:
            # return if message is a response
            JSONRPCResponse.parse_raw(message)
            return
        except Exception:
            pass

        try:
            msg = JSONRPCNotification.parse_raw(message)
            logger.debug(f"Received notification: {msg}")
        except Exception as e:
            logger.error(f"Error parsing notification: {e}")
            return
        try:
            params = JSONRPCNotficationParams.parse_obj(msg.params)
            logger.trace(f"Notification params: {params}")
        except Exception as e:
            logger.error(f"Error parsing notification params: {e}")
            return

        self.callback_map[params.subId](params)
        return

    def connect(self):
        self.websocket.run_forever(ping_interval=10, ping_timeout=5)

    def close(self):
        # unsubscribe from all subscriptions
        for subId in self.callback_map.keys():
            req = JSONRPCRequest(
                method=JSONRPCMethods.UNSUBSCRIBE.value,
                params=JSONRPCUnsubscribeParams(subId=subId).dict(),
                id=self.id_counter,
            )
            logger.trace(f"Unsubscribing: {req.json()}")
            self.websocket.send(req.json())
            self.id_counter += 1

        self.websocket.keep_running = False
        self.websocket.close()

    def wait_until_connected(self):
        while not self.websocket.sock or not self.websocket.sock.connected:
            time.sleep(0.025)

    def subscribe(
        self, kind: JSONRPCSubscriptionKinds, filters: List[str], callback: Callable
    ):
        self.wait_until_connected()
        subId = random_hash()
        req = JSONRPCRequest(
            method=JSONRPCMethods.SUBSCRIBE.value,
            params=JSONRPCSubscribeParams(
                kind=kind, filters=filters, subId=subId
            ).dict(),
            id=self.id_counter,
        )
        logger.trace(f"Subscribing: {req.json()}")
        self.websocket.send(req.json())
        self.id_counter += 1
        self.callback_map[subId] = callback
