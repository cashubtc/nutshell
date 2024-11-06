import asyncio
import hashlib
import math
from datetime import datetime
from os import urandom
from typing import AsyncGenerator, Dict, List, Optional

from bolt11 import (
    Bolt11,
    Feature,
    Features,
    FeatureState,
    MilliSatoshi,
    TagChar,
    Tags,
    decode,
    encode,
)

from ..core.base import Amount, MeltQuote, Unit
from ..core.helpers import fee_reserve
from ..core.models import PostMeltQuoteRequest
from ..core.settings import settings
from .base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)


class FakeWallet(LightningBackend):
    unit: Unit
    fake_btc_price = 1e8 / 1337
    paid_invoices_queue: asyncio.Queue[Bolt11] = asyncio.Queue(0)
    payment_secrets: Dict[str, str] = dict()
    created_invoices: List[Bolt11] = []
    paid_invoices_outgoing: List[Bolt11] = []
    paid_invoices_incoming: List[Bolt11] = []
    secret: str = "FAKEWALLET SECRET"
    privkey: str = hashlib.pbkdf2_hmac(
        "sha256",
        secret.encode(),
        b"FakeWallet",
        2048,
        32,
    ).hex()

    supported_units = {Unit.sat, Unit.msat, Unit.usd, Unit.eur}

    supports_incoming_payment_stream: bool = True
    supports_description: bool = True

    def __init__(self, unit: Unit = Unit.sat, **kwargs):
        self.assert_unit_supported(unit)
        self.unit = unit

    async def status(self) -> StatusResponse:
        return StatusResponse(error_message=None, balance=1337)

    async def mark_invoice_paid(self, invoice: Bolt11, delay=True) -> None:
        if invoice in self.paid_invoices_incoming:
            return
        if not settings.fakewallet_brr:
            return
        if settings.fakewallet_delay_incoming_payment and delay:
            await asyncio.sleep(settings.fakewallet_delay_incoming_payment)
        self.paid_invoices_incoming.append(invoice)
        await self.paid_invoices_queue.put(invoice)

    def create_dummy_bolt11(self, payment_hash: str) -> Bolt11:
        tags = Tags()
        tags.add(TagChar.payment_hash, payment_hash)
        tags.add(TagChar.payment_secret, urandom(32).hex())
        return Bolt11(
            currency="bc",
            amount_msat=MilliSatoshi(1337),
            date=int(datetime.now().timestamp()),
            tags=tags,
        )

    async def create_invoice(
        self,
        amount: Amount,
        memo: Optional[str] = None,
        description_hash: Optional[bytes] = None,
        unhashed_description: Optional[bytes] = None,
        expiry: Optional[int] = None,
        payment_secret: Optional[bytes] = None,
    ) -> InvoiceResponse:
        self.assert_unit_supported(amount.unit)
        tags = Tags()
        tags.add(
            TagChar.features,
            Features.from_feature_list(
                {Feature.payment_secret: FeatureState.supported}
            ),
        )

        if description_hash:
            tags.add(TagChar.description_hash, description_hash.hex())
        elif unhashed_description:
            tags.add(
                TagChar.description_hash,
                hashlib.sha256(unhashed_description).hexdigest(),
            )
        else:
            tags.add(TagChar.description, memo or "")

        tags.add(TagChar.expire_time, expiry or 3600)

        if payment_secret:
            secret = payment_secret.hex()
        else:
            secret = urandom(32).hex()
        tags.add(TagChar.payment_secret, secret)

        payment_hash = hashlib.sha256(secret.encode()).hexdigest()

        tags.add(TagChar.payment_hash, payment_hash)

        self.payment_secrets[payment_hash] = secret

        amount_msat = 0
        if self.unit == Unit.sat:
            amount_msat = MilliSatoshi(amount.to(Unit.msat, round="up").amount)
        elif self.unit == Unit.usd or self.unit == Unit.eur:
            amount_msat = MilliSatoshi(
                math.ceil(amount.amount / self.fake_btc_price * 1e9)
            )
        else:
            raise NotImplementedError()

        bolt11 = Bolt11(
            currency="bc",
            amount_msat=amount_msat,
            date=int(datetime.now().timestamp()),
            tags=tags,
        )

        if bolt11 not in self.created_invoices:
            self.created_invoices.append(bolt11)
        else:
            raise ValueError("Invoice already created")

        payment_request = encode(bolt11, self.privkey)

        if settings.fakewallet_brr:
            asyncio.create_task(self.mark_invoice_paid(bolt11))

        return InvoiceResponse(
            ok=True, checking_id=payment_hash, payment_request=payment_request
        )

    async def pay_invoice(self, quote: MeltQuote, fee_limit: int) -> PaymentResponse:
        if settings.fakewallet_pay_invoice_state_exception:
            raise Exception("FakeWallet pay_invoice exception")

        invoice = decode(quote.request)

        if settings.fakewallet_delay_outgoing_payment:
            await asyncio.sleep(settings.fakewallet_delay_outgoing_payment)

        if settings.fakewallet_pay_invoice_state:
            return PaymentResponse(
                result=PaymentResult[settings.fakewallet_pay_invoice_state],
                checking_id=invoice.payment_hash,
                fee=Amount(unit=self.unit, amount=1),
                preimage=self.payment_secrets.get(invoice.payment_hash) or "0" * 64,
            )

        if invoice.payment_hash in self.payment_secrets or settings.fakewallet_brr:
            if invoice not in self.paid_invoices_outgoing:
                self.paid_invoices_outgoing.append(invoice)
            else:
                raise ValueError("Invoice already paid")

            return PaymentResponse(
                result=PaymentResult.SETTLED,
                checking_id=invoice.payment_hash,
                fee=Amount(unit=self.unit, amount=1),
                preimage=self.payment_secrets.get(invoice.payment_hash) or "0" * 64,
            )
        else:
            return PaymentResponse(
                result=PaymentResult.FAILED,
                error_message="Only internal invoices can be used!",
            )

    async def get_invoice_status(self, checking_id: str) -> PaymentStatus:
        await self.mark_invoice_paid(self.create_dummy_bolt11(checking_id), delay=False)
        paid_chceking_ids = [i.payment_hash for i in self.paid_invoices_incoming]
        if checking_id in paid_chceking_ids:
            return PaymentStatus(result=PaymentResult.SETTLED)
        else:
            return PaymentStatus(
                result=PaymentResult.UNKNOWN, error_message="Invoice not found"
            )

    async def get_payment_status(self, checking_id: str) -> PaymentStatus:
        if settings.fakewallet_payment_state_exception:
            raise Exception("FakeWallet get_payment_status exception")
        if settings.fakewallet_payment_state:
            return PaymentStatus(
                result=PaymentResult[settings.fakewallet_payment_state]
            )
        return PaymentStatus(result=PaymentResult.SETTLED)

    async def get_payment_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        invoice_obj = decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."

        if self.unit == Unit.sat:
            amount_msat = int(invoice_obj.amount_msat)
            fees_msat = fee_reserve(amount_msat)
            fees = Amount(unit=Unit.msat, amount=fees_msat)
            amount = Amount(unit=Unit.msat, amount=amount_msat)
        elif self.unit == Unit.usd or self.unit == Unit.eur:
            amount_usd = math.ceil(invoice_obj.amount_msat / 1e9 * self.fake_btc_price)
            amount = Amount(unit=self.unit, amount=amount_usd)
            fees = Amount(unit=self.unit, amount=2)
        else:
            raise NotImplementedError()

        return PaymentQuoteResponse(
            checking_id=invoice_obj.payment_hash,
            fee=fees.to(self.unit, round="up"),
            amount=amount.to(self.unit, round="up"),
        )

    async def paid_invoices_stream(self) -> AsyncGenerator[str, None]:
        while True:
            value: Bolt11 = await self.paid_invoices_queue.get()
            yield value.payment_hash
