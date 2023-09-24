import asyncio
import hashlib
import random
from datetime import datetime
from os import urandom
from typing import AsyncGenerator, Optional, Set

from bolt11.decode import decode
from bolt11.encode import encode
from bolt11.models.tags import TagChar, Tags
from bolt11.types import Bolt11, MilliSatoshi

from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)

BRR = True


class FakeWallet(Wallet):
    """https://github.com/lnbits/lnbits"""

    queue: asyncio.Queue = asyncio.Queue(0)
    paid_invoices: Set[str] = set()
    secret: str = "FAKEWALLET SECRET"
    privkey: str = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        ("FakeWallet").encode(),
        2048,
        32,
    ).hex()

    async def status(self) -> StatusResponse:
        return StatusResponse(None, 1337)

    async def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        expiry: Optional[int] = None,
        payment_secret: Optional[bytes] = None,
        **_,
    ) -> InvoiceResponse:
        tags = Tags()
        if description_hash:
            tags.add(TagChar.description_hash, description_hash.hex())
        elif unhashed_description:
            tags.add(
                TagChar.description_hash,
                hashlib.sha256(unhashed_description).hexdigest(),
            )
        else:
            tags.add(TagChar.description, memo or "")

        if expiry:
            tags.add(TagChar.expire_time, expiry)

        # random hash
        checking_id = (
            self.privkey[:6]
            + hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[6:]
        )

        tags.add(TagChar.payment_hash, checking_id)

        if payment_secret:
            secret = payment_secret.hex()
        else:
            secret = urandom(32).hex()
        tags.add(TagChar.payment_secret, secret)

        bolt11 = Bolt11(
            currency="bc",
            amount_msat=MilliSatoshi(amount * 1000),
            date=int(datetime.now().timestamp()),
            tags=tags,
        )

        payment_request = encode(bolt11, self.privkey)
        return InvoiceResponse(True, checking_id, payment_request)

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        try:
            invoice = decode(bolt11)
        except Exception as exc:
            return PaymentResponse(ok=False, error_message=str(exc))

        if invoice.payment_hash[:6] == self.privkey[:6] or BRR:
            await self.queue.put(invoice)
            self.paid_invoices.add(invoice.payment_hash)
            return PaymentResponse(True, invoice.payment_hash, 0)
        else:
            return PaymentResponse(
                ok=False, error_message="Only internal invoices can be used!"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        # paid = random.random() > 0.7
        # return PaymentStatus(paid)
        paid = checking_id in self.paid_invoices or BRR
        return PaymentStatus(paid or None)

    async def get_payment_status(self, _: str) -> PaymentStatus:
        return PaymentStatus(None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            value: Bolt11 = await self.queue.get()
            yield value.payment_hash
