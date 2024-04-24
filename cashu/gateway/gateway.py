import asyncio
import os
import time
from typing import Dict, List, Mapping

import bolt11
from loguru import logger

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
from ..core.htlc import HTLCSecret
from ..core.secret import Secret, SecretKind
from ..core.settings import settings
from ..lightning.base import (
    LightningBackend,
)
from ..mint.ledger import Ledger
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


class Gateway(Ledger):
    locks: Dict[str, asyncio.Lock] = {}  # holds mutex locks
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    db: Database
    wallets: Dict[str, Wallet] = {}

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
        self.gwcrud = crud

    async def init_wallets(self):
        for mint in settings.gateway_mint_urls:
            logger.info(f"Loading wallet for mint: {mint}")
            self.wallets[mint] = await Wallet.with_db(
                mint,
                db=os.path.join(settings.cashu_dir, "gateway"),
                name="gateway",
            )
            await self.wallets[mint].load_proofs()
            await self.wallets[mint].load_mint()

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

    async def gateway_melt_quote(
        self, melt_quote_request: GatewayMeltQuoteRequest
    ) -> GatewayMeltQuoteResponse:
        if melt_quote_request.mint not in self.wallets.keys():
            raise TransactionError(
                f"mint does not match gateway mint: {self.wallets.keys()}"
            )
        mint = melt_quote_request.mint
        pubkey = await self.wallets[mint].create_p2pk_pubkey()
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

        await self.gwcrud.store_melt_quote(mint=mint, quote=melt_quote, db=self.db)
        assert melt_quote.expiry
        return GatewayMeltQuoteResponse(
            pubkey=pubkey,
            quote=melt_quote.quote,
            amount=melt_quote.amount,
            expiry=melt_quote.expiry,
            paid=melt_quote.paid,
        )

    async def gateway_get_melt_quote(
        self, quote_id: str, check_quote_with_backend: bool = False
    ) -> GatewayMeltQuoteResponse:
        mint, melt_quote = await self.gwcrud.get_melt_quote(
            quote_id=quote_id, db=self.db
        )
        if mint not in self.wallets.keys():
            raise TransactionError("mint not found")
        pubkey = await self.wallets[mint].create_p2pk_pubkey()
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
                await self.gwcrud.update_melt_quote(quote=melt_quote, db=self.db)

        return GatewayMeltQuoteResponse(
            pubkey=pubkey,
            quote=melt_quote.quote,
            amount=melt_quote.amount,
            expiry=melt_quote.expiry,
            paid=melt_quote.paid,
        )

    def _check_proofs(self, wallet: Wallet, proofs: List[Proof]):
        if not proofs:
            raise TransactionError("no proofs")
        # make sure there are no duplicate proofs
        if len(proofs) != len(set(p.secret for p in proofs)):
            raise TransactionError("duplicate proofs")
        if not all([self._verify_secret_criteria(p) for p in proofs]):
            raise TransactionError("secrets do not match criteria.")
        for proof in proofs:
            # check if proof keysets are from the gateway's wallet's mint
            if proof.id not in wallet.keysets:
                raise TransactionError("proof keysets not valid")

    def _verify_htlc(
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

    async def gateway_melt(
        self,
        *,
        proofs: List[Proof],
        quote: str,
    ) -> GatewayMeltResponse:
        try:
            mint, melt_quote = await self.gwcrud.get_melt_quote(
                quote_id=quote, db=self.db
            )
        except ValueError as e:
            raise TransactionError(str(e))
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
        if mint not in self.wallets:
            raise TransactionError("mint not found")
        wallet = self.wallets[mint]
        pubkey = await wallet.create_p2pk_pubkey()
        # get the backend for the unit
        invoice = bolt11.decode(melt_quote.request)
        # check proofs
        self._check_proofs(wallet, proofs)
        # check if signatures of proofs are valid using DLEQ proofs
        wallet.verify_proofs_dleq(proofs=proofs)
        # check if the HTLCs are valid
        for proof in proofs:
            self._verify_htlc(
                proof=proof,
                hashlock=invoice.payment_hash,
                pubkey=pubkey,
                expiry=melt_quote.expiry,
            )

        # proofs are ok

        # pay the backend
        logger.debug(f"Lightning: pay invoice {melt_quote.request}")
        payment = await self.backends[method][unit].pay_invoice(
            melt_quote, melt_quote.fee_reserve * 1000
        )
        logger.debug(
            f"Lightning payment – Ok: {payment.ok}: preimage: {payment.preimage},"
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
        await self.gwcrud.update_melt_quote(quote=melt_quote, db=self.db)

        # redeem proofs
        signatures = await wallet.sign_p2pk_proofs(proofs)
        for p, s in zip(proofs, signatures):
            p.witness = HTLCWitness(preimage=payment.preimage, signature=s).json()

        print(f"Balance: {Amount(unit=unit, amount=wallet.available_balance)}")
        await wallet.redeem(proofs)
        print(f"Balance: {Amount(unit=unit, amount=wallet.available_balance)}")

        return GatewayMeltResponse(
            paid=True,
            payment_preimage=payment.preimage,
        )
