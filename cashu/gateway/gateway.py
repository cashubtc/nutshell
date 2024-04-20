import os
import time
from typing import List, Mapping

import bolt11
from loguru import logger

from cashu.core.htlc import HTLCSecret
from cashu.core.secret import Secret, SecretKind

from ..core.base import (
    Amount,
    HTLCWitness,
    MeltQuote,
    Method,
    Proof,
    Unit,
)
from ..core.crypto.keys import random_hash
from ..core.db import Database
from ..core.errors import LightningError, TransactionError
from ..core.settings import settings
from ..lightning.base import (
    LightningBackend,
)
from ..wallet.wallet import Wallet
from .crud import GatewayCrudSqlite
from .models import (
    GatewayMeltQuoteRequest,
    GatewayMeltQuoteResponse,
    GatewayMeltResponse,
)

# This makes sure that we require ecash htlc lock time and
# invoice lock time at least LOCKTIME_SAFETY seconds apart
LOCKTIME_SAFETY = 60  # 1 minute


class Gateway:
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    db: Database
    wallet: Wallet
    pubkey: str

    def __init__(
        self,
        db: Database,
        seed: str,
        backends: Mapping[Method, Mapping[Unit, LightningBackend]],
        crud=GatewayCrudSqlite(),
    ):
        self.db = db
        self.seed = seed
        self.backends = backends
        self.crud = crud

    async def init_wallet(self):
        self.wallet = await Wallet.with_db(
            settings.mint_url,
            db=os.path.join(settings.cashu_dir, "gateway"),
            name="gateway",
        )
        await self.wallet.load_proofs()
        await self.wallet.load_mint()
        self.pubkey = await self.wallet.create_p2pk_pubkey()
        return self.wallet

        # ------- STARTUP -------

    async def startup_gateway(self):
        await self._startup_gateway()
        # await self._check_pending_proofs_and_melt_quotes()

    async def _startup_gateway(self):
        for method in self.backends:
            for unit in self.backends[method]:
                logger.info(
                    f"Using {self.backends[method][unit].__class__.__name__} backend for"
                    f" method: '{method.name}' and unit: '{unit.name}'"
                )
                status = await self.backends[method][unit].status()
                if status.error_message:
                    logger.warning(
                        "The backend for"
                        f" {self.backends[method][unit].__class__.__name__} isn't"
                        f" working properly: '{status.error_message}'",
                        RuntimeWarning,
                    )
                logger.info(f"Backend balance: {status.balance} {unit.name}")

        logger.info(f"Data dir: {settings.cashu_dir}")

    async def melt_quote(
        self, melt_quote_request: GatewayMeltQuoteRequest
    ) -> GatewayMeltQuoteResponse:
        request = melt_quote_request.request
        invoice = bolt11.decode(pr=request)
        amount_msat = bolt11.decode(pr=request).amount_msat
        if amount_msat is None:
            raise Exception("amount_msat is None")
        amount = amount_msat // 1000

        # add fees to the amount
        if settings.gateway_bolt11_sat_fee_ppm:
            amount += amount * settings.gateway_bolt11_sat_fee_ppm // 1000000
        if settings.gateway_bolt11_sat_base_fee:
            amount += settings.gateway_bolt11_sat_base_fee

        unit = Unit[melt_quote_request.unit]
        if unit not in self.backends[Method.bolt11]:
            raise Exception("unit not supported by backend")
        method = Method.bolt11

        # not internal, get payment quote by backend
        payment_quote = await self.backends[method][unit].get_payment_quote(request)
        if not payment_quote.checking_id:
            raise TransactionError("quote has no checking id")
        # make sure the backend returned the amount with a correct unit
        if not payment_quote.amount.unit == unit:
            raise TransactionError("payment quote amount units do not match")
        # fee from the backend must be in the same unit as the amount
        if not payment_quote.fee.unit == unit:
            raise TransactionError("payment quote fee units do not match")

        if not invoice.date or not invoice.expiry:
            raise TransactionError("invoice does not have date or expiry")

        # check if invoice is already paid
        payment_quote_check = await self.backends[method][unit].get_payment_status(
            payment_quote.checking_id
        )
        if payment_quote_check.paid:
            raise TransactionError("invoice is already paid")

        invoice_expiry = invoice.date + invoice.expiry

        melt_quote = MeltQuote(
            quote=random_hash(),
            method=method.name,
            request=request,
            checking_id=payment_quote.checking_id,
            unit=unit.name,
            amount=amount,
            fee_reserve=payment_quote.fee.amount,
            paid=False,
            created_time=0,
            paid_time=0,
            fee_paid=0,
            expiry=invoice_expiry + LOCKTIME_SAFETY,
        )

        await self.crud.store_melt_quote(quote=melt_quote, db=self.db)
        assert melt_quote.expiry
        return GatewayMeltQuoteResponse(
            pubkey=self.pubkey,
            quote=melt_quote.quote,
            amount=melt_quote.amount,
            expiry=melt_quote.expiry,
            paid=melt_quote.paid,
        )

    async def get_melt_quote(
        self, quote_id: str, check_quote_with_backend: bool = False
    ) -> GatewayMeltQuoteResponse:
        melt_quote = await self.crud.get_melt_quote(quote_id=quote_id, db=self.db)
        if not melt_quote:
            raise TransactionError("quote not found")
        if not melt_quote.expiry:
            raise TransactionError("quote does not have expiry")
        if check_quote_with_backend and not melt_quote.paid:
            unit = Unit[melt_quote.unit]
            if unit not in self.backends[Method.bolt11]:
                raise Exception("unit not supported by backend")
            method = Method.bolt11
            # get the backend for the unit
            payment_quote = await self.backends[method][unit].get_payment_status(
                melt_quote.checking_id
            )
            if payment_quote.paid:
                melt_quote.paid = True
                melt_quote.paid_time = int(time.time())
                await self.crud.update_melt_quote(quote=melt_quote, db=self.db)

        return GatewayMeltQuoteResponse(
            pubkey=self.pubkey,
            quote=melt_quote.quote,
            amount=melt_quote.amount,
            expiry=melt_quote.expiry,
            paid=melt_quote.paid,
        )

    def _verify_input_spending_conditions(
        self,
        proof: Proof,
        hashlock: str,
        pubkey: str,
        expiry: int,
    ):
        secret = Secret.deserialize(proof.secret)
        if SecretKind(secret.kind) != SecretKind.HTLC:
            raise TransactionError("proof secret kind is not HTLC")
        htlc_secret = HTLCSecret.from_secret(secret)
        if htlc_secret.data != hashlock:
            raise TransactionError("proof secret data does not match hashlock")
        hashlock_pubkeys = htlc_secret.tags.get_tag_all("pubkeys")
        if not hashlock_pubkeys:
            raise TransactionError("proof secret does not have hashlock pubkeys")
        is_valid = False
        for htlc_pubkey in hashlock_pubkeys:
            if htlc_pubkey == pubkey:
                is_valid = True
                break
        if not is_valid:
            raise TransactionError("proof secret pubkey does not match hashlock pubkey")

        locktime = htlc_secret.tags.get_tag("locktime")
        if locktime:
            locktime = int(locktime)
            if locktime < expiry:
                raise TransactionError("proof secret locktime is not valid")
        else:
            logger.error(f"locktime: {locktime}")
            raise TransactionError("no locktime in proof secret")

    async def melt(
        self,
        *,
        proofs: List[Proof],
        quote: str,
    ) -> GatewayMeltResponse:
        melt_quote = await self.crud.get_melt_quote(quote_id=quote, db=self.db)
        if not melt_quote:
            raise TransactionError("quote not found")
        if melt_quote.paid:
            raise TransactionError("quote is already paid")
        if melt_quote.amount != sum(p.amount for p in proofs):
            raise TransactionError("proofs amount does not match quote")
        if not melt_quote.expiry or melt_quote.expiry < int(time.time()):
            raise TransactionError("quote expired")
        unit = Unit[melt_quote.unit]
        if unit not in self.backends[Method.bolt11]:
            raise Exception("unit not supported by backend")
        method = Method.bolt11

        # get the backend for the unit
        invoice = bolt11.decode(melt_quote.request)
        # check proofs
        self.wallet.verify_proofs_dleq(proofs=proofs)
        for proof in proofs:
            self._verify_input_spending_conditions(
                proof=proof,
                hashlock=invoice.payment_hash,
                pubkey=self.pubkey,
                expiry=melt_quote.expiry,
            )

        # proofs are ok

        # pay the backend
        logger.debug(f"Lightning: pay invoice {melt_quote.request}")
        payment = await self.backends[method][unit].pay_invoice(
            melt_quote, melt_quote.fee_reserve * 1000
        )
        logger.debug(
            f"Melt – Ok: {payment.ok}: preimage: {payment.preimage},"
            f" fee: {payment.fee.str() if payment.fee is not None else 'None'}"
        )
        if not payment.ok:
            raise LightningError(
                f"Lightning payment unsuccessful. {payment.error_message}"
            )
        if payment.fee:
            melt_quote.fee_paid = payment.fee.to(to_unit=unit, round="up").amount
        if payment.preimage:
            melt_quote.proof = payment.preimage
        # set quote as paid
        melt_quote.paid = True
        melt_quote.paid_time = int(time.time())
        await self.crud.update_melt_quote(quote=melt_quote, db=self.db)

        # redeem proofs
        signatures = await self.wallet.sign_p2pk_proofs(proofs)
        for p, s in zip(proofs, signatures):
            p.witness = HTLCWitness(preimage=payment.preimage, signature=s).json()

        print(f"Balance: {Amount(unit=unit, amount=self.wallet.available_balance)}")
        await self.wallet.redeem(proofs)
        print(f"Balance: {Amount(unit=unit, amount=self.wallet.available_balance)}")

        return GatewayMeltResponse(
            paid=True,
            payment_preimage=payment.preimage,
        )
