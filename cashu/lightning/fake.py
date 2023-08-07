import asyncio
import hashlib
import random
from datetime import datetime
from typing import AsyncGenerator, Optional, Set, Union

from bolt11.decode import decode
from bolt11.encode import encode
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
        **_,
    ) -> InvoiceResponse:
        tags: dict[str, Union[str, int]] = {}
        if description_hash:
            tags["h"] = bytes.hex(description_hash)
        elif unhashed_description:
            tags["h"] = hashlib.sha256(unhashed_description).hexdigest()
        else:
            tags["d"] = memo or ""

        if expiry:
            tags["x"] = expiry
        # random hash
        checking_id = (
            self.privkey[:6]
            + hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()[6:]
        )
        tags["p"] = checking_id
        bolt11 = Bolt11(
            currency="bc",
            amount_msat=MilliSatoshi(amount * 1000),
            date=int(datetime.now().timestamp()),
            tags=tags,
        )
        payment_request = encode(bolt11, self.privkey)
        return InvoiceResponse(True, checking_id, payment_request)

    async def pay_invoice(self, bolt11: str, fee_limit_msat: int) -> PaymentResponse:
        invoice = decode(bolt11)
        if not invoice.payment_hash:
            return PaymentResponse(
                ok=False, error_message="Missing payment_hash in invoice!"
            )
        if invoice.payment_hash[:6] == self.privkey[:6] or BRR:
            await self.queue.put(invoice)
            self.paid_invoices.add(invoice.payment_hash)
            return PaymentResponse(True, invoice.payment_hash, 0)
        else:
            return PaymentResponse(
                ok=False, error_message="Only internal invoices can be used!"
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        paid = checking_id in self.paid_invoices or BRR
        return PaymentStatus(paid or None)

    async def get_payment_status(self, _: str) -> PaymentStatus:
        return PaymentStatus(None)

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            value: Bolt11 = await self.queue.get()
            assert value.payment_hash, "Missing payment_hash in paid_invoices_stream"
            yield value.payment_hash
