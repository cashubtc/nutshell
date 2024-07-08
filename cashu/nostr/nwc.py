import asyncio
import json
import os

from typing import Any, List, Optional, Union
from enum import Enum
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qs
from loguru import logger

from .event import NWCRequest, EventKind
from .filter import Filter, Filters
from .client.client import NostrClient
from .key import PublicKey
from .message_type import ClientMessageType


class Nip47Method(Enum):
    get_balance = "get_balance"
    make_invoice = "make_invoice"
    pay_invoice = "pay_invoice"
    lookup_invoice = "lookup_invoice"
    get_info = "get_info"


class Nip47GetInfoResponse(BaseModel):
    alias: str
    color: str
    pubkey: str
    network: str
    block_height: int
    block_hash: str
    methods: List[str]


class Nip47GetBalanceResponse(BaseModel):
    balance: int  # in msats


class Nip47PayInvoiceRequest(BaseModel):
    invoice: str
    amount: Optional[int] = None


class Nip47PayInvoiceResponse(BaseModel):
    preimage: str


class Nip47MakeInvoiceRequest(BaseModel):
    amount: int
    description: Optional[str] = None
    description_hash: Optional[str] = None
    expiry: Optional[int] = None


# Note: last I checked, Alby and Mutiny can't lookup by invoice, only by payment_hash
class Nip47LookupInvoiceRequest(BaseModel):
    invoice: Optional[str] = None
    payment_hash: Optional[str] = None


class Nip47TransactionType(Enum):
    incoming = "incoming"
    outgoing = "outgoing"


class Nip47Transaction(BaseModel):
    type: Nip47TransactionType
    payment_hash: str
    amount: int
    fees_paid: int
    invoice: Optional[str]
    description: Optional[str]
    description_hash: Optional[str]
    preimage: Optional[str]
    created_at: int
    settled_at: Optional[int]
    expires_at: Optional[int]


class Nip47ErrorCode(Enum):
    """https://github.com/nostr-protocol/nips/blob/master/47.md#error-codes"""

    RATE_LIMITED = "RATE_LIMITED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    INSUFFICIENT_BALANCE = "INSUFFICIENT_BALANCE"
    RESTRICTED = "RESTRICTED"
    UNAUTHORIZED = "UNAUTHORIZED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    INTERNAL = "INTERNAL"
    OTHER = "OTHER"


class Nip47Error(Exception):
    def __init__(self, code: Nip47ErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(message)

    def __str__(self):
        return f"NWC error: {self.code} - {self.message}"


class NWCOptions(BaseModel):
    wallet_pubkey: str
    relays: Optional[List[str]]
    secret: Optional[str]
    lud16: Optional[str]
    pubkey: Optional[str]


class NWCClient(NostrClient):
    """
    https://github.com/nostr-protocol/nips/blob/master/47.md#nip-47
    """

    def __init__(self, nostrWalletConnectUrl: str):
        assert nostrWalletConnectUrl is not None, "Nostr Wallet Connect URL is required"
        options = NWCClient.parse_nwc_url(nostrWalletConnectUrl)
        if options.relays is None:
            raise ValueError("Missing relays in NWC URL")
        if options.secret is None:
            raise ValueError("Missing secret in NWC URL")
        self.wallet_pubkey = PublicKey(raw_bytes=bytes.fromhex(options.wallet_pubkey))
        self.relays = options.relays
        self.secret = options.secret
        super().__init__(private_key=self.secret, relays=self.relays, connect=True)

    @staticmethod
    def parse_nwc_url(url: str) -> NWCOptions:
        """
        https://github.com/nostr-protocol/nips/blob/master/47.md#nostr-wallet-connect-uri
        Args:
            url: The Nostr Wallet Connect URL. ie. `nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss%3A%2F%2Frelay.damus.io&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c`
        Returns:
            The connection details.
        """
        # Replace different protocol schemes with http for uniform parsing
        url = (
            url.replace("nostrwalletconnect://", "http://")
            .replace("nostr+walletconnect://", "http://")
            .replace("nostrwalletconnect:", "http://")
            .replace("nostr+walletconnect:", "http://")
        )
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        relays = query.get("relay")
        secret = query.get("secret")
        wallet_pubkey_hex = parsed.hostname
        options = NWCOptions(
            relays=relays, wallet_pubkey=wallet_pubkey_hex, secret=secret[0]
        )
        return options

    async def get_balance(self) -> Nip47GetBalanceResponse:
        def result_validator(result: dict) -> bool:
            valid = "balance" in result
            if not valid:
                logger.warning(f"Expected 'balance' in NWC response: {result}")
            return valid

        res = await self.execute_nip47_request(
            Nip47Method.get_balance, {}, result_validator
        )
        return Nip47GetBalanceResponse(**res)

    async def get_info(self) -> Nip47GetInfoResponse:
        def result_validator(result: dict) -> bool:
            valid = all(
                key in result
                for key in [
                    "methods",
                ]
            )
            return valid

        res = await self.execute_nip47_request(
            Nip47Method.get_info, {}, result_validator
        )
        return Nip47GetInfoResponse(**res)

    async def create_invoice(
        self, request: Nip47MakeInvoiceRequest
    ) -> Nip47Transaction:
        def result_validator(result: dict) -> bool:
            valid = all(
                key in result
                for key in [
                    "invoice",
                    "payment_hash",
                ]
            )
            if not valid:
                logger.warning(
                    f"Expected 'invoice' and 'payment_hash' in NWC response: {result}"
                )
            return valid

        res = await self.execute_nip47_request(
            Nip47Method.make_invoice, request.dict(), result_validator
        )
        return Nip47Transaction(**res)

    async def lookup_invoice(
        self, request: Nip47LookupInvoiceRequest
    ) -> Nip47Transaction:
        def result_validator(result: dict) -> bool:
            valid = all(
                key in result
                for key in [
                    "payment_hash",
                    "amount",
                    "fees_paid",
                    "created_at",
                    "expires_at",
                ]
            )
            if not valid:
                logger.warning(
                    f"Expected 'payment_hash', 'amount', 'fees_paid', 'created_at', 'expires_at' in NWC response: {result}"
                )
            return valid

        res = await self.execute_nip47_request(
            Nip47Method.lookup_invoice, request.dict(), result_validator
        )
        return Nip47Transaction(**res)

    async def pay_invoice(
        self, request: Nip47PayInvoiceRequest
    ) -> Nip47PayInvoiceResponse:
        def result_validator(result: dict) -> bool:
            valid = "preimage" in result
            if not valid:
                logger.warning(f"Expected 'preimage' in NWC response: {result}")
            return valid

        res = await self.execute_nip47_request(
            Nip47Method.pay_invoice, request.dict(), result_validator
        )
        return Nip47PayInvoiceResponse(**res)

    async def subscribe_to_response(
        self,
        request_id: str,
    ) -> asyncio.Future:
        """
        Subscribe to kind 23195 events authored by the NWC wallet and tagged with request event's ID.
        Args:
            request_id: The ID of the request event.
        Returns:
            The response event's decrypted content.
        Raises:
            Nip47Error: If the response event contains an error.
        """
        filters = Filters(
            [
                Filter(
                    kinds=[EventKind.NWC_RESPONSE],
                    authors=[self.wallet_pubkey.hex()],
                    event_refs=[request_id],
                )
            ]
        )

        # publish subscription
        sub_id = os.urandom(4).hex()
        self.relay_manager.add_subscription(sub_id, filters)
        request = [ClientMessageType.REQUEST, sub_id]
        request.extend(filters.to_json_array())
        message = json.dumps(request)
        self.relay_manager.publish_message(message)

        logger.debug(f"Subscribed to filters: {filters.to_json_array()}")
        future = asyncio.Future()

        # loop until we get a response
        while any(
            [r.subscriptions.get(sub_id) for r in self.relay_manager.relays.values()]
        ):
            while self.relay_manager.message_pool.has_events():
                event_msg = self.relay_manager.message_pool.get_event()
                try:
                    decrypted_content = self.private_key.decrypt_message(
                        event_msg.event.content, event_msg.event.public_key
                    )
                    response = json.loads(decrypted_content)
                    logger.debug(f"Got NWC response: {response}")
                except Exception as e:
                    future.set_exception(e)
                    return future

                if response.get("error") is not None:
                    future.set_exception(
                        Nip47Error(
                            code=Nip47ErrorCode(response.get("error").get("code")),
                            message=response.get("error").get("message", None),
                        )
                    )
                    return future
                future.set_result(response.get("result"))
                # close this subscription
                try:
                    [
                        r.close_subscription(sub_id)
                        for r in self.relay_manager.relays.values()
                    ]
                except KeyError:
                    # if subscription is already closed,
                    pass
            if future.done():
                break
            await asyncio.sleep(0.1)
        return future

    async def execute_nip47_request(
        self, method: Nip47Method, params: Any, result_validator
    ) -> dict:
        """
        Sends an NWC request and resolves the response.
        Args:
            method: The Nip47Method to execute.
            params: The request parameters.
            result_validator: A function that validates the response result.
        Returns:

        """
        logger.debug(f"executing NWC request: {method} with params: {params}")

        command = {
            "method": method.value,
            "params": params,
        }

        nwc_request = NWCRequest(
            cleartext_content=json.dumps(command),
            recipient_pubkey=self.wallet_pubkey.hex(),
            public_key=self.public_key.hex(),
        )

        self.private_key.sign_event(nwc_request)

        assert nwc_request.verify(), "Failed to sign NWC request"

        # subscribe to response before sending request
        response_future = self.subscribe_to_response(
            nwc_request.id,
        )

        # send request
        request_json = nwc_request.to_message()
        self.relay_manager.publish_message(request_json)

        # wait for and handle response
        res = await asyncio.wait_for(response_future, timeout=10)
        if not result_validator(res.result()):
            raise Exception("Invalid NWC response")
        return res.result()
