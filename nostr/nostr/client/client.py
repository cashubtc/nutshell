from typing import *
import ssl
import time
import json
import os
import base64

from nostr.event import Event
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType
from nostr.key import PrivateKey, PublicKey

from nostr.filter import Filter, Filters
from nostr.event import Event, EventKind
from nostr.relay_manager import RelayManager
from nostr.message_type import ClientMessageType

# from aes import AESCipher
from . import cbc


class NostrClient:
    relays = [
        "wss://nostr.zebedee.cloud",
        "wss://nostr-relay.digitalmob.ro",
    ]  # ["wss://nostr.oxtr.dev"]  # ["wss://relay.nostr.info"] "wss://nostr-pub.wellorder.net"  "ws://91.237.88.218:2700", "wss://nostrrr.bublina.eu.org", ""wss://nostr-relay.freeberty.net"", , "wss://nostr.oxtr.dev", "wss://relay.nostr.info", "wss://nostr-pub.wellorder.net" , "wss://relayer.fiatjaf.com", "wss://nodestr.fmt.wiz.biz/", "wss://no.str.cr", "wss://nostr-relay.digitalmob.ro"
    relay_manager = RelayManager()
    private_key: PrivateKey
    public_key: PublicKey

    def __init__(self, privatekey_hex: str = "", relays: List[str] = []):
        self.generate_keys(privatekey_hex)

        if len(relays):
            self.relays = relays

        for relay in self.relays:
            self.relay_manager.add_relay(relay)
        self.relay_manager.open_connections(
            {"cert_reqs": ssl.CERT_NONE}
        )  # NOTE: This disables ssl certificate verification

    def close(self):
        self.relay_manager.close_connections()

    def generate_keys(self, privatekey_hex: str = None):
        pk = bytes.fromhex(privatekey_hex) if privatekey_hex else None
        self.private_key = PrivateKey(pk)
        self.public_key = self.private_key.public_key
        print(f"Private key: {self.private_key.bech32()} ({self.private_key.hex()})")
        print(f"Public key: {self.public_key.bech32()} ({self.public_key.hex()})")

    def post(self, message: str):
        event = Event(self.public_key.hex(), message, kind=EventKind.TEXT_NOTE)
        event.sign(self.private_key.hex())
        message = json.dumps([ClientMessageType.EVENT, event.to_json_object()])
        # print("Publishing message:")
        # print(message)
        self.relay_manager.publish_message(message)

    def get_post(self, sender_publickey: PublicKey):
        filters = Filters(
            [Filter(authors=[sender_publickey.hex()], kinds=[EventKind.TEXT_NOTE])]
        )
        subscription_id = os.urandom(4).hex()
        self.relay_manager.add_subscription(subscription_id, filters)

        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        # print("Subscribing to events:")
        # print(message)
        self.relay_manager.publish_message(message)

        message_received = False
        while True:
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()
                print(event_msg.event.content)
                message_received = True
                break
            else:
                time.sleep(0.1)

    def dm(self, message: str, to_pubkey: PublicKey):

        shared_secret = self.private_key.compute_shared_secret(to_pubkey.hex())

        # print("shared secret: ", shared_secret.hex())
        # print("plain text:", message)
        aes = cbc.AESCipher(key=shared_secret)
        iv, enc_text = aes.encrypt(message)
        # print("encrypt iv: ", iv)
        content = f"{base64.b64encode(enc_text).decode('utf-8')}?iv={base64.b64encode(iv).decode('utf-8')}"

        event = Event(
            self.public_key.hex(),
            content,
            tags=[["p", to_pubkey.hex()]],
            kind=EventKind.ENCRYPTED_DIRECT_MESSAGE,
        )
        event.sign(self.private_key.hex())
        event_message = json.dumps([ClientMessageType.EVENT, event.to_json_object()])
        # print("DM message:")
        # print(event_message)

        time.sleep(1)
        self.relay_manager.publish_message(event_message)

    def get_dm(self, sender_publickey: PublicKey, callback_func=None):
        filters = Filters(
            [
                Filter(
                    kinds=[EventKind.ENCRYPTED_DIRECT_MESSAGE],
                    tags={"#p": [sender_publickey.hex()]},
                )
            ]
        )
        subscription_id = os.urandom(4).hex()
        self.relay_manager.add_subscription(subscription_id, filters)

        request = [ClientMessageType.REQUEST, subscription_id]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        # print("Subscribing to events:")
        # print(message)
        self.relay_manager.publish_message(message)

        while True:
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()

                if "?iv=" in event_msg.event.content:
                    try:
                        shared_secret = self.private_key.compute_shared_secret(
                            event_msg.event.public_key
                        )
                        # print("shared secret: ", shared_secret.hex())
                        # print("plain text:", message)
                        aes = cbc.AESCipher(key=shared_secret)
                        enc_text_b64, iv_b64 = event_msg.event.content.split("?iv=")
                        iv = base64.decodebytes(iv_b64.encode("utf-8"))
                        enc_text = base64.decodebytes(enc_text_b64.encode("utf-8"))
                        # print("decrypt iv: ", iv)
                        dec_text = aes.decrypt(iv, enc_text)
                        # print(f"From {event_msg.event.public_key[:5]}...: {dec_text}")
                        if callback_func:
                            callback_func(event_msg.event, dec_text)
                    except:
                        pass
                # else:
                # print(f"\nFrom {event_msg.event.public_key[:5]}...: {event_msg.event.content}")
                break
            time.sleep(0.1)

    async def subscribe(self):
        while True:
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()
                print(event_msg.event.content)
                break
            time.sleep(0.1)
