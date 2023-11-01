import asyncio
import hashlib
import random
from datetime import datetime
from os import urandom
from typing import AsyncGenerator, Optional, Set

from bolt11 import (
    Bolt11,
    MilliSatoshi,
    TagChar,
    Tags,
    decode,
    encode,
)

from .base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
    Wallet,
)

BRR = True
DELAY_PAYMENT = False
STOCHASTIC_INVOICE = False


class FakeWallet(Wallet):
    """https://github.com/lnbits/lnbits"""

    queue: asyncio.Queue[Bolt11] = asyncio.Queue(0)
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
        return StatusResponse(error_message=None, balance_msat=1337)

    async def create_invoice(
        self,
        amount: int,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        expiry: Optional[int] = None,
        payment_secret: Optional[bytes] = None,
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

        return InvoiceResponse(
            ok=True, checking_id=checking_id, payment_request=payment_request
        )

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        invoice = decode(bolt11)

        if DELAY_PAYMENT:
            await asyncio.sleep(5)

        if invoice.payment_hash[:6] == self.privkey[:6] or BRR:
            await self.queue.put(invoice)
            self.paid_invoices.add(invoice.payment_hash)
            return PaymentResponse(
                ok=True, checking_id=invoice.payment_hash, fee_msat=0
            )
        else:
            return PaymentResponse(
                ok=False, error_message="Only internal invoices can be used!"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        if STOCHASTIC_INVOICE:
            paid = random.random() > 0.7
            return PaymentStatus(paid=paid)
        paid = checking_id in self.paid_invoices or BRR
        return PaymentStatus(paid=paid or None)

    async def get_payment_status(self, _: str) -> PaymentStatus:
        return PaymentStatus(paid=None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            value: Bolt11 = await self.queue.get()
            yield value.payment_hash
