import json
import time
from queue import Queue
from threading import Lock
from websocket import WebSocketApp
from .event import Event
from .filter import Filters
from .message_pool import MessagePool
from .message_type import RelayMessageType
from .subscription import Subscription


class RelayPolicy:
    def __init__(self, should_read: bool = True, should_write: bool = True) -> None:
        self.should_read = should_read
        self.should_write = should_write

    def to_json_object(self) -> dict[str, bool]:
        return {"read": self.should_read, "write": self.should_write}


class Relay:
    def __init__(
        self,
        url: str,
        policy: RelayPolicy,
        message_pool: MessagePool,
        subscriptions: dict[str, Subscription] = {},
    ) -> None:
        self.url = url
        self.policy = policy
        self.message_pool = message_pool
        self.subscriptions = subscriptions
        self.connected: bool = False
        self.reconnect: bool = True
        self.error_counter: int = 0
        self.error_threshold: int = 0
        self.num_received_events: int = 0
        self.num_sent_events: int = 0
        self.num_subscriptions: int = 0
        self.ssl_options: dict = {}
        self.proxy: dict = {}
        self.lock = Lock()
        self.queue = Queue()
        self.ws = WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
            on_ping=self._on_ping,
            on_pong=self._on_pong,
        )

    def connect(self, ssl_options: dict = None, proxy: dict = None):
        self.ssl_options = ssl_options
        self.proxy = proxy
        if not self.connected:
            self.ws.run_forever(
                sslopt=ssl_options,
                http_proxy_host=None if proxy is None else proxy.get("host"),
                http_proxy_port=None if proxy is None else proxy.get("port"),
                proxy_type=None if proxy is None else proxy.get("type"),
                ping_interval=5,
            )

    def close(self):
        self.ws.close()

    def check_reconnect(self):
        try:
            self.close()
        except:
            pass
        self.connected = False
        if self.reconnect:
            time.sleep(1)
            self.connect(self.ssl_options, self.proxy)

    @property
    def ping(self):
        ping_ms = int((self.ws.last_pong_tm - self.ws.last_ping_tm) * 1000)
        return ping_ms if self.connected and ping_ms > 0 else 0

    def publish(self, message: str):
        self.queue.put(message)

    def queue_worker(self):
        while True:
            if self.connected:
                message = self.queue.get()
                self.num_sent_events += 1
                self.ws.send(message)
            else:
                time.sleep(0.1)

    def add_subscription(self, id, filters: Filters):
        with self.lock:
            self.subscriptions[id] = Subscription(id, filters)

    def close_subscription(self, id: str) -> None:
        with self.lock:
            self.subscriptions.pop(id)

    def update_subscription(self, id: str, filters: Filters) -> None:
        with self.lock:
            subscription = self.subscriptions[id]
            subscription.filters = filters

    def to_json_object(self) -> dict:
        return {
            "url": self.url,
            "policy": self.policy.to_json_object(),
            "subscriptions": [
                subscription.to_json_object()
                for subscription in self.subscriptions.values()
            ],
        }

    def _on_open(self, class_obj):
        self.connected = True
        pass

    def _on_close(self, class_obj, status_code, message):
        self.connected = False
        pass

    def _on_message(self, class_obj, message: str):
        if self._is_valid_message(message):
            self.num_received_events += 1
            self.message_pool.add_message(message, self.url)

    def _on_error(self, class_obj, error):
        self.connected = False
        self.error_counter += 1
        if self.error_threshold and self.error_counter > self.error_threshold:
            pass
        else:
            self.check_reconnect()

    def _on_ping(self, class_obj, message):
        return

    def _on_pong(self, class_obj, message):
        return

    def _is_valid_message(self, message: str) -> bool:
        message = message.strip("\n")
        if not message or message[0] != "[" or message[-1] != "]":
            return False

        message_json = json.loads(message)
        message_type = message_json[0]
        if not RelayMessageType.is_valid(message_type):
            return False
        if message_type == RelayMessageType.EVENT:
            if not len(message_json) == 3:
                return False

            subscription_id = message_json[1]
            with self.lock:
                if subscription_id not in self.subscriptions:
                    return False

            e = message_json[2]
            event = Event(
                e["content"],
                e["pubkey"],
                e["created_at"],
                e["kind"],
                e["tags"],
                e["sig"],
            )
            if not event.verify():
                return False

            with self.lock:
                subscription = self.subscriptions[subscription_id]

            if subscription.filters and not subscription.filters.match(event):
                return False

        return True
