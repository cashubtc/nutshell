import asyncio
import time
from typing import Dict, List, Optional

import bolt11
from loguru import logger

from ...core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    MeltQuoteState,
    Method,
    MintQuote,
    MintQuoteState,
    Proof,
    Unit,
)
from ...core.crypto.keys import random_hash
from ...core.errors import (
    LightningPaymentFailedError,
    NotAllowedError,
    TransactionError,
)
from ...core.helpers import sum_proofs
from ...core.models import (
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
)
from ...core.settings import settings
from ...lightning.base import (
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
)
from ..protocols import SupportsEvents
from .blind_signatures import LedgerBlindSignatures


class LedgerMelt(LedgerBlindSignatures, SupportsEvents):
    disable_melt: bool

    def create_internal_melt_quote(
        self, mint_quote: MintQuote, melt_quote: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        unit, method = self._verify_and_get_unit_method(
            melt_quote.unit, Method.bolt11.name
        )
        # NOTE: we normalize the request to lowercase to avoid case sensitivity
        # This works with Lightning but might not work with other methods
        request = melt_quote.request.lower()

        if not request == mint_quote.request:
            raise TransactionError("bolt11 requests do not match")
        if not mint_quote.unit == melt_quote.unit:
            raise TransactionError("units do not match")
        if not mint_quote.method == method.name:
            raise TransactionError("methods do not match")
        if mint_quote.paid:
            raise TransactionError("mint quote already paid")
        if mint_quote.issued:
            raise TransactionError("mint quote already issued")
        if not mint_quote.unpaid:
            raise TransactionError("mint quote is not unpaid")

        if not mint_quote.checking_id:
            raise TransactionError("mint quote has no checking id")
        if melt_quote.is_mpp:
            raise TransactionError("internal payments do not support mpp")

        internal_fee = Amount(unit, 0)  # no internal fees
        amount = Amount(unit, mint_quote.amount)

        payment_quote = PaymentQuoteResponse(
            checking_id=mint_quote.checking_id,
            amount=amount,
            fee=internal_fee,
        )
        logger.info(
            f"Issuing internal melt quote: {request} ->"
            f" {mint_quote.quote} ({amount.str()} + {internal_fee.str()} fees)"
        )

        return payment_quote

    def validate_payment_quote(
        self, melt_quote: PostMeltQuoteRequest, payment_quote: PaymentQuoteResponse
    ):
        # payment quote validation
        unit, method = self._verify_and_get_unit_method(
            melt_quote.unit, Method.bolt11.name
        )
        if not payment_quote.checking_id:
            raise Exception("quote has no checking id")
        # verify that payment quote amount is as expected
        if (
            melt_quote.is_mpp
            and melt_quote.mpp_amount != payment_quote.amount.to(Unit.msat).amount
        ):
            logger.error(
                f"expected {payment_quote.amount.to(Unit.msat).amount} msat but got {melt_quote.mpp_amount}"
            )
            raise TransactionError("quote amount not as requested")
        # make sure the backend returned the amount with a correct unit
        if not payment_quote.amount.unit == unit:
            raise TransactionError("payment quote amount units do not match")
        # fee from the backend must be in the same unit as the amount
        if not payment_quote.fee.unit == unit:
            raise TransactionError("payment quote fee units do not match")

    async def melt_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PostMeltQuoteResponse:
        """Creates a melt quote and stores it in the database.

        Args:
            melt_quote (PostMeltQuoteRequest): Melt quote request.

        Raises:
            Exception: Quote invalid.
            Exception: Quote already paid.
            Exception: Quote already issued.

        Returns:
            PostMeltQuoteResponse: Melt quote response.
        """
        if settings.mint_bolt11_disable_melt:
            raise NotAllowedError("Melting with bol11 is disabled.")

        unit, method = self._verify_and_get_unit_method(
            melt_quote.unit, Method.bolt11.name
        )

        # NOTE: we normalize the request to lowercase to avoid case sensitivity
        # This works with Lightning but might not work with other methods
        request = melt_quote.request.lower()

        # check if there is a mint quote with the same payment request
        # so that we would be able to handle the transaction internally
        # and therefore respond with internal transaction fees (0 for now)
        mint_quote = await self.crud.get_mint_quote(request=request, db=self.db)
        if mint_quote and mint_quote.unit == melt_quote.unit:
            # check if the melt quote is partial and error if it is.
            # it's just not possible to handle this case
            if melt_quote.is_mpp:
                raise TransactionError("internal mpp not allowed.")
            payment_quote = self.create_internal_melt_quote(mint_quote, melt_quote)
        else:
            # not internal
            # verify that the backend supports mpp if the quote request has an amount
            if melt_quote.is_mpp and not self.backends[method][unit].supports_mpp:
                raise TransactionError("backend does not support mpp.")
            # get payment quote by backend
            payment_quote = await self.backends[method][unit].get_payment_quote(
                melt_quote=melt_quote
            )

        self.validate_payment_quote(melt_quote, payment_quote)

        # verify that the amount of the proofs is not larger than the maximum allowed
        if (
            settings.mint_max_melt_bolt11_sat
            and payment_quote.amount.to(unit).amount > settings.mint_max_melt_bolt11_sat
        ):
            raise NotAllowedError(
                f"Maximum melt amount is {settings.mint_max_melt_bolt11_sat} sat."
            )

        # We assume that the request is a bolt11 invoice, this works since we
        # support only the bol11 method for now.
        invoice_obj = bolt11.decode(melt_quote.request)
        if not invoice_obj.amount_msat:
            raise TransactionError("invoice has no amount.")
        # we set the expiry of this quote to the expiry of the bolt11 invoice
        now = int(time.time())
        expiry = None
        if settings.melt_quote_ttl is not None:
            expiry = now + settings.melt_quote_ttl
        elif invoice_obj.expiry is not None:
            expiry = invoice_obj.date + invoice_obj.expiry

        quote = MeltQuote(
            quote=random_hash(),
            method=method.name,
            request=request,
            checking_id=payment_quote.checking_id,
            unit=unit.name,
            amount=payment_quote.amount.to(unit).amount,
            state=MeltQuoteState.unpaid,
            fee_reserve=payment_quote.fee.to(unit).amount,
            created_time=now,
            expiry=expiry,
        )
        await self.db_write._store_melt_quote(quote)
        await self.events.submit(quote)

        return PostMeltQuoteResponse(
            quote=quote.quote,
            amount=quote.amount,
            unit=quote.unit,
            request=quote.request,
            fee_reserve=quote.fee_reserve,
            paid=quote.paid,  # deprecated
            state=quote.state.value,
            expiry=quote.expiry,
        )

    async def get_melt_quote(self, quote_id: str, rollback_unknown=False) -> MeltQuote:
        """Returns a melt quote.

        If the melt quote is pending, checks status of the payment with the backend.
            - If settled, sets the quote as paid and invalidates pending proofs (commit).
            - If failed, sets the quote as unpaid and unsets pending proofs (rollback).
            - If rollback_unknown is set, do the same for unknown states as for failed states.

        Args:
            quote_id (str): ID of the melt quote.
            rollback_unknown (bool, optional): Rollback unknown payment states to unpaid. Defaults to False.

        Raises:
            Exception: Quote not found.

        Returns:
            MeltQuote: Melt quote object.
        """
        melt_quote = await self.crud.get_melt_quote(quote_id=quote_id, db=self.db)
        if not melt_quote:
            raise Exception("quote not found")

        unit, method = self._verify_and_get_unit_method(
            melt_quote.unit, melt_quote.method
        )

        # we only check the state with the backend if there is no associated internal
        # mint quote for this melt quote
        is_internal = await self.crud.get_mint_quote(
            request=melt_quote.request, db=self.db
        )

        if melt_quote.pending and not is_internal:
            logger.debug(
                "Lightning: checking outgoing Lightning payment"
                f" {melt_quote.checking_id}"
            )
            status: PaymentStatus = await self.backends[method][
                unit
            ].get_payment_status(melt_quote.checking_id)
            logger.debug(f"State: {status.result}")
            if status.settled:
                logger.debug(f"Setting quote {quote_id} as paid")
                melt_quote.state = MeltQuoteState.paid
                if status.fee:
                    melt_quote.fee_paid = status.fee.to(unit).amount
                if status.preimage:
                    melt_quote.payment_preimage = status.preimage
                melt_quote.paid_time = int(time.time())
                pending_proofs = await self.crud.get_pending_proofs_for_quote(
                    quote_id=quote_id, db=self.db
                )

                # change to compensate wallet for overpaid fees
                melt_outputs = await self.crud.get_blinded_messages_melt_id(
                    melt_id=quote_id, db=self.db
                )
                if melt_outputs:
                    total_provided = sum_proofs(pending_proofs)
                    input_fees = self.get_fees_for_proofs(pending_proofs)
                    fee_reserve_provided = (
                        total_provided - melt_quote.amount - input_fees
                    )
                    return_promises = await self._generate_change_promises(
                        fee_provided=fee_reserve_provided,
                        fee_paid=melt_quote.fee_paid,
                        outputs=melt_outputs,
                        melt_id=quote_id,
                        keyset=self.keysets[melt_outputs[0].id],
                    )
                    melt_quote.change = return_promises

                # Calculate fees
                proofs_by_keyset: Dict[str, List[Proof]] = {}
                for p in pending_proofs:
                    proofs_by_keyset.setdefault(p.id, []).append(p)
                keyset_fees = {}
                for keyset_id, keyset_proofs in proofs_by_keyset.items():
                    keyset_fees[keyset_id] = self.get_fees_for_proofs(keyset_proofs)

                melt_quote = (
                    await self.db_write.set_melt_quote_paid_and_invalidate_proofs(
                        quote=melt_quote,
                        proofs=pending_proofs,
                        keysets=self.keysets,
                        keyset_fees=keyset_fees,
                    )
                )

            if status.failed or (rollback_unknown and status.unknown):
                logger.debug(f"Setting quote {quote_id} as unpaid")
                pending_proofs = await self.crud.get_pending_proofs_for_quote(
                    quote_id=quote_id, db=self.db
                )
                melt_quote = await self.db_write.unset_melt_quote_pending_and_proofs(
                    quote=melt_quote,
                    proofs=pending_proofs,
                    keysets=self.keysets,
                    state=MeltQuoteState.unpaid,
                )

        return melt_quote

    async def melt_mint_settle_internally(
        self, melt_quote: MeltQuote, proofs: List[Proof]
    ) -> MeltQuote:
        """Settles a melt quote internally if there is a mint quote with the same payment request.

        `proofs` are passed to determine the ecash input transaction fees for this melt quote.

        Args:
            melt_quote (MeltQuote): Melt quote to settle.
            proofs (List[Proof]): Proofs provided for paying the Lightning invoice.

        Raises:
            Exception: Melt quote already paid.
            Exception: Melt quote already issued.

        Returns:
            MeltQuote: Settled melt quote.
        """
        # first we check if there is a mint quote with the same payment request
        # so that we can handle the transaction internally without the backend
        mint_quote = await self.crud.get_mint_quote(
            request=melt_quote.request, db=self.db
        )
        if not mint_quote:
            return melt_quote

        # settle externally if units are different
        if mint_quote.unit != melt_quote.unit:
            return melt_quote

        # we settle the transaction internally
        if melt_quote.paid:
            raise TransactionError("melt quote already paid")

        # verify amounts from bolt11 invoice
        bolt11_request = melt_quote.request
        invoice_obj = bolt11.decode(bolt11_request)

        if not invoice_obj.amount_msat:
            raise TransactionError("invoice has no amount.")
        if not mint_quote.amount == melt_quote.amount:
            raise TransactionError("amounts do not match")
        if not bolt11_request == mint_quote.request:
            raise TransactionError("bolt11 requests do not match")
        if not mint_quote.method == melt_quote.method:
            raise TransactionError("methods do not match")

        if mint_quote.paid:
            raise TransactionError("mint quote already paid")
        if mint_quote.issued:
            raise TransactionError("mint quote already issued")

        if mint_quote.state != MintQuoteState.unpaid:
            raise TransactionError("mint quote is not unpaid")

        logger.info(
            f"Settling bolt11 payment internally: {melt_quote.quote} ->"
            f" {mint_quote.quote} ({melt_quote.amount} {melt_quote.unit})"
        )

        melt_quote.fee_paid = 0  # no internal fees
        melt_quote.state = MeltQuoteState.paid
        melt_quote.paid_time = int(time.time())

        mint_quote.state = MintQuoteState.paid
        mint_quote.paid_time = melt_quote.paid_time

        async with self.db.get_connection() as conn:
            await self.crud.update_melt_quote(quote=melt_quote, db=self.db, conn=conn)
            await self.crud.update_mint_quote(quote=mint_quote, db=self.db, conn=conn)

        await self.events.submit(melt_quote)
        await self.events.submit(mint_quote)

        return melt_quote

    async def async_melt(
        self,
        *,
        proofs: List[Proof],
        quote: str,
        outputs: Optional[List[BlindedMessage]] = None,
    ) -> PostMeltQuoteResponse:
        """Invalidates proofs and pays a Lightning invoice asynchronously.

        Args:
            proofs (List[Proof]): Proofs provided for paying the Lightning invoice
            quote (str): ID of the melt quote.
            outputs (Optional[List[BlindedMessage]]): Blank outputs for returning overpaid fees to the wallet.

        Returns:
            PostMeltQuoteResponse: Melt quote response with pending state.
        """
        # get melt quote
        melt_quote = await self.get_melt_quote(quote_id=quote)
        if not melt_quote:
            raise TransactionError("melt quote not found")
        if not melt_quote.unpaid:
            raise TransactionError(f"melt quote is not unpaid: {melt_quote.state}")

        # Launch actual melt task
        async def melt_task():
            try:
                await self.melt(proofs=proofs, quote=quote, outputs=outputs)
            except Exception as e:
                logger.error(f"Error in background melt task: {e}")

        asyncio.create_task(melt_task())

        melt_quote.state = MeltQuoteState.pending
        return PostMeltQuoteResponse.from_melt_quote(melt_quote)

    async def melt(
        self,
        *,
        proofs: List[Proof],
        quote: str,
        outputs: Optional[List[BlindedMessage]] = None,
    ) -> PostMeltQuoteResponse:
        """Invalidates proofs and pays a Lightning invoice.

        Args:
            proofs (List[Proof]): Proofs provided for paying the Lightning invoice
            quote (str): ID of the melt quote.
            outputs (Optional[List[BlindedMessage]]): Blank outputs for returning overpaid fees to the wallet.

        Raises:
            e: Lightning payment unsuccessful

        Returns:
            PostMeltQuoteResponse: Melt quote response.
        """
        # make sure we're allowed to melt
        if self.disable_melt and settings.mint_disable_melt_on_error:
            raise NotAllowedError("Melt is disabled. Please contact the operator.")

        # get melt quote and check if it was already paid
        melt_quote = await self.get_melt_quote(quote_id=quote)
        if not melt_quote.unpaid:
            raise TransactionError(f"melt quote is not unpaid: {melt_quote.state}")

        unit, method = self._verify_and_get_unit_method(
            melt_quote.unit, melt_quote.method
        )

        # make sure that the proofs are in the same unit as the quote
        self._verify_proofs_unit(proofs, expected_unit=unit)

        # make sure that the outputs (for fee return) are in the same unit as the quote
        if outputs:
            # _verify_outputs checks if all outputs have the same unit
            await self._verify_outputs(
                outputs, skip_amount_check=True, expected_unit=unit
            )

        # verify SIG_ALL signatures
        message_to_sign = (
            "".join([p.secret for p in proofs] + [o.B_ for o in outputs or []]) + quote
        )
        self._verify_sigall_spending_conditions(proofs, outputs or [], message_to_sign)

        # verify that the amount of the input proofs is equal to the amount of the quote
        total_provided = sum_proofs(proofs)
        input_fees = self.get_fees_for_proofs(proofs)
        total_needed = melt_quote.amount + melt_quote.fee_reserve + input_fees
        # we need the fees specifically for lightning to return the overpaid fees
        fee_reserve_provided = total_provided - melt_quote.amount - input_fees
        if total_provided < total_needed:
            raise TransactionError(
                f"not enough inputs provided for melt. Provided: {total_provided}, needed: {total_needed}"
            )
        if fee_reserve_provided < melt_quote.fee_reserve:
            raise TransactionError(
                f"not enough fee reserve provided for melt. Provided fee reserve: {fee_reserve_provided}, needed: {melt_quote.fee_reserve}"
            )

        # verify inputs and their spending conditions
        # note, we do not verify outputs here, as they are only used for returning overpaid fees
        # We must have called _verify_outputs here already! (see above)
        await self.verify_inputs_and_outputs(proofs=proofs)

        # set quote and proofs to pending to avoid race conditions
        melt_quote = await self.db_write.verify_and_set_melt_quote_pending(
            quote=melt_quote, proofs=proofs, keysets=self.keysets
        )

        # store the change outputs
        if outputs:
            await self._store_blinded_messages(outputs, melt_id=melt_quote.quote)

        # if the melt corresponds to an internal mint, mark both as paid
        melt_quote = await self.melt_mint_settle_internally(melt_quote, proofs)
        # quote not paid yet (not internal), pay it with the backend
        if not melt_quote.paid:
            logger.debug(f"Lightning: pay invoice {melt_quote.request}")
            try:
                payment = await self.backends[method][unit].pay_invoice(
                    melt_quote, melt_quote.fee_reserve * 1000
                )
                logger.debug(
                    f"Melt – Result: {payment.result.name}: preimage: {payment.preimage},"
                    f" fee: {payment.fee.str() if payment.fee is not None else 'None'}"
                )
                if (
                    payment.checking_id
                    and payment.checking_id != melt_quote.checking_id
                ):
                    logger.warning(
                        f"pay_invoice returned different checking_id: {payment.checking_id} than melt quote: {melt_quote.checking_id}. Will use it for potentially checking payment status later."
                    )
                    melt_quote.checking_id = payment.checking_id
                    await self.crud.update_melt_quote(quote=melt_quote, db=self.db)
            except Exception as e:
                logger.error(f"Exception during pay_invoice: {e}")
                payment = PaymentResponse(
                    result=PaymentResult.UNKNOWN,
                    error_message=str(e),
                )

            match payment.result:
                case PaymentResult.FAILED | PaymentResult.UNKNOWN:
                    # explicitly check payment status for failed or unknown payment states
                    checking_id = payment.checking_id or melt_quote.checking_id
                    logger.debug(
                        f"Payment state is {payment.result.name}.{' Error: ' + payment.error_message + '.' if payment.error_message else ''} Checking status for {checking_id}."
                    )
                    try:
                        status = await self.backends[method][unit].get_payment_status(
                            checking_id
                        )
                    except Exception as e:
                        # Something went wrong. We might have lost connection to the backend. Keep transaction pending and return.
                        logger.error(
                            f"Lightning backend error: could not check payment status. Proofs for melt quote {melt_quote.quote} are stuck as PENDING.\nError: {e}"
                        )
                        self.disable_melt = True
                        return PostMeltQuoteResponse.from_melt_quote(melt_quote)

                    match status.result:
                        case PaymentResult.FAILED | PaymentResult.UNKNOWN:
                            # Everything as expected. Payment AND a status check both agree on a failure. We roll back the transaction.
                            await self.db_write.unset_melt_quote_pending_and_proofs(
                                quote=melt_quote,
                                proofs=proofs,
                                keysets=self.keysets,
                                state=MeltQuoteState.unpaid,
                            )
                            if status.error_message:
                                logger.error(
                                    f"Status check error: {status.error_message}"
                                )
                            raise LightningPaymentFailedError(
                                f"Lightning payment failed{': ' + payment.error_message if payment.error_message else ''}."
                            )
                        case _:
                            # Something went wrong with our implementation or the backend. Status check returned different result than payment. Keep transaction pending and return.
                            logger.error(
                                f"Payment state was {payment.result} but additional payment state check returned {status.result.name}. Proofs for melt quote {melt_quote.quote} are stuck as PENDING."
                            )
                            self.disable_melt = True
                            return PostMeltQuoteResponse.from_melt_quote(melt_quote)

                case PaymentResult.SETTLED:
                    # payment successful
                    if payment.fee:
                        melt_quote.fee_paid = payment.fee.to(
                            to_unit=unit, round="up"
                        ).amount
                    if payment.preimage:
                        melt_quote.payment_preimage = payment.preimage
                    # set quote as paid
                    melt_quote.state = MeltQuoteState.paid
                    melt_quote.paid_time = int(time.time())
                    # NOTE: This is the only branch for a successful payment

                case PaymentResult.PENDING | _:
                    logger.debug(
                        f"Lightning payment is {payment.result.name}: {payment.checking_id}"
                    )
                    return PostMeltQuoteResponse.from_melt_quote(melt_quote)

        # melt was successful (either internal or via backend), invalidate proofs
        # prepare change to compensate wallet for overpaid fees
        return_promises: List[BlindedSignature] = []
        if outputs:
            return_promises = await self._generate_change_promises(
                fee_provided=fee_reserve_provided,
                fee_paid=melt_quote.fee_paid,
                outputs=outputs,
                melt_id=melt_quote.quote,
                keyset=self.keysets[outputs[0].id],
            )

        melt_quote.change = return_promises

        # Calculate fees
        proofs_by_keyset: Dict[str, List[Proof]] = {}
        for p in proofs:
            proofs_by_keyset.setdefault(p.id, []).append(p)
        keyset_fees = {}
        for keyset_id, keyset_proofs in proofs_by_keyset.items():
            keyset_fees[keyset_id] = self.get_fees_for_proofs(keyset_proofs)

        melt_quote = await self.db_write.set_melt_quote_paid_and_invalidate_proofs(
            quote=melt_quote,
            proofs=proofs,
            keysets=self.keysets,
            keyset_fees=keyset_fees,
        )

        return PostMeltQuoteResponse.from_melt_quote(melt_quote)
