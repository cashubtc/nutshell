import json
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
        self.lock = Lock()
        self.ws = WebSocketApp(
            url,
            on_open=self._on_open,
            on_message=self._on_message,
            on_error=self._on_error,
            on_close=self._on_close,
        )

    def connect(self, ssl_options: dict = None):
        self.ws.run_forever(sslopt=ssl_options)

    def close(self):
        self.ws.close()

    def publish(self, message: str):
        self.ws.send(message)

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
        pass

    def _on_close(self, class_obj, status_code, message):
        pass

    def _on_message(self, class_obj, message: str):
        if self._is_valid_message(message):
            self.message_pool.add_message(message, self.url)

    def _on_error(self, class_obj, error):
        pass

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
                e["pubkey"],
                e["content"],
                e["created_at"],
                e["kind"],
                e["tags"],
                e["id"],
                e["sig"],
            )
            if not event.verify():
                return False

            with self.lock:
                subscription = self.subscriptions[subscription_id]

            if not subscription.filters.match(event):
                return False

        return True
