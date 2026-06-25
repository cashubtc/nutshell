import time
from typing import List, Optional

import bolt11
from loguru import logger

from ...core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    Method,
    MintQuote,
    MintQuoteState,
)
from ...core.crypto.keys import generate_uuid_v7
from ...core.errors import (
    BatchDuplicateQuotesError,
    CashuError,
    LightningError,
    NotAllowedError,
    QuoteAlreadyIssuedError,
    QuoteNotPaidError,
    QuoteSignatureInvalidError,
    TransactionAmountExceedsLimitError,
    TransactionError,
)
from ...core.models import (
    PostMintBatchRequest,
    PostMintQuoteCheckRequest,
    PostMintQuoteRequest,
)
from ...core.settings import settings
from ...lightning.base import InvoiceResponse, PaymentStatus
from ..protocols import SupportsEvents, SupportsWatchdog
from .blind_signatures import LedgerBlindSignatures


class LedgerMint(LedgerBlindSignatures, SupportsWatchdog, SupportsEvents):
    async def mint_quote(self, quote_request: PostMintQuoteRequest) -> MintQuote:
        """Creates a mint quote and stores it in the database.

        Args:
            quote_request (PostMintQuoteRequest): Mint quote request.

        Raises:
            Exception: Quote creation failed.

        Returns:
            MintQuote: Mint quote object.
        """
        logger.trace("called request_mint")
        if not quote_request.amount > 0:
            raise TransactionError("amount must be positive")
        if (
            settings.mint_max_mint_bolt11_sat
            and quote_request.amount > settings.mint_max_mint_bolt11_sat
        ):
            raise TransactionAmountExceedsLimitError(
                f"Maximum mint amount is {settings.mint_max_mint_bolt11_sat} sat."
            )
        if settings.mint_bolt11_disable_mint:
            raise NotAllowedError("Minting with bolt11 is disabled.")

        unit, method = self._verify_and_get_unit_method(
            quote_request.unit, Method.bolt11.name
        )

        if (
            quote_request.description
            and not self.backends[method][unit].supports_description
        ):
            raise NotAllowedError("Backend does not support descriptions.")

        # Check maximum balance.
        # TODO: Allow setting MINT_MAX_BALANCE per unit
        if settings.mint_max_balance:
            balance, fees_paid = await self.get_unit_balance_and_fees(unit, db=self.db)
            if balance + quote_request.amount > settings.mint_max_balance:
                raise NotAllowedError("Mint has reached maximum balance.")

        logger.trace(f"requesting invoice for {unit.str(quote_request.amount)}")
        invoice_response: InvoiceResponse = await self.backends[method][
            unit
        ].create_invoice(
            amount=Amount(unit=unit, amount=quote_request.amount),
            memo=quote_request.description,
        )
        logger.trace(
            f"got invoice {invoice_response.payment_request} with checking id"
            f" {invoice_response.checking_id}"
        )

        if not (invoice_response.payment_request and invoice_response.checking_id):
            raise LightningError("could not fetch bolt11 payment request from backend")

        # get invoice expiry time
        invoice_obj = bolt11.decode(invoice_response.payment_request)

        # NOTE: we normalize the request to lowercase to avoid case sensitivity
        # This works with Lightning but might not work with other methods
        request = invoice_response.payment_request.lower()

        now = int(time.time())
        expiry = None
        if settings.mint_quote_ttl is not None:
            expiry = now + settings.mint_quote_ttl
        elif invoice_obj.expiry is not None:
            expiry = invoice_obj.date + invoice_obj.expiry

        quote = MintQuote(
            quote=generate_uuid_v7(),
            method=method.name,
            request=request,
            checking_id=invoice_response.checking_id,
            unit=quote_request.unit,
            amount=quote_request.amount,
            state=MintQuoteState.unpaid,
            created_time=now,
            expiry=expiry,
            pubkey=quote_request.pubkey,
        )
        await self.crud.store_mint_quote(quote=quote, db=self.db)
        await self.events.submit(quote)

        return quote

    async def get_mint_quote(self, quote_id: str) -> MintQuote:
        """Returns a mint quote. If the quote is not paid, checks with the backend if the associated request is paid.

        Args:
            quote_id (str): ID of the mint quote.

        Raises:
            Exception: Quote not found.

        Returns:
            MintQuote: Mint quote object.
        """
        quote = await self.crud.get_mint_quote(quote_id=quote_id, db=self.db)
        if not quote:
            raise Exception("quote not found")

        unit, method = self._verify_and_get_unit_method(quote.unit, quote.method)

        if quote.unpaid:
            if not quote.checking_id:
                raise CashuError("quote has no checking id")

            now = int(time.time())
            updated = await self.crud.try_update_mint_quote_last_checked(
                quote_id=quote_id,
                last_checked=now,
                rate_limit=settings.mint_quote_backend_check_rate_limit,
                db=self.db,
            )
            if not updated:
                logger.trace(
                    f"Lightning: checking invoice {quote.checking_id} skipped due to rate limit"
                )
                return quote
            quote.last_checked = now

            logger.trace(f"Lightning: checking invoice {quote.checking_id}")
            status: PaymentStatus = await self.backends[method][
                unit
            ].get_invoice_status(quote.checking_id)
            if status.settled:
                # change state to paid in one transaction, it could have been marked paid
                # by the invoice listener in the mean time
                async with self.db.get_connection(
                    lock_table="mint_quotes",
                    lock_select_statement="quote = :quote",
                    lock_parameters={"quote": quote_id},
                ) as conn:
                    quote = await self.crud.get_mint_quote(
                        quote_id=quote_id, db=self.db, conn=conn
                    )
                    if not quote:
                        raise Exception("quote not found")
                    if quote.unpaid:
                        logger.trace(f"Setting quote {quote_id} as paid")
                        quote.state = MintQuoteState.paid
                        quote.paid_time = now
                        quote.last_checked = now
                        quote.updated_at = now
                        await self.crud.update_mint_quote(
                            quote=quote, db=self.db, conn=conn
                        )
                        await self.events.submit(quote)

        return quote

    async def mint_quote_check(
        self, payload: PostMintQuoteCheckRequest
    ) -> List[MintQuote]:
        """Batch check mint quotes.

        Args:
            payload (PostMintQuoteCheckRequest): Request payload containing quote IDs.

        Returns:
            List[MintQuote]: List of mint quotes matching the request.
        """
        quotes: List[MintQuote] = []
        for quote_id in payload.quotes:
            quote = await self.get_mint_quote(quote_id)
            if not quote:
                raise TransactionError(f"quote {quote_id} not found")
            quotes.append(quote)
        return quotes

    async def mint(
        self,
        *,
        outputs: List[BlindedMessage],
        quote_id: str,
        signature: Optional[str] = None,
    ) -> List[BlindedSignature]:
        """Mints new coins if quote with `quote_id` was paid. Ingest blind messages `outputs` and returns blind signatures `promises`.

        Args:
            outputs (List[BlindedMessage]): Outputs (blinded messages) to sign.
            quote_id (str): Mint quote id.
            witness (Optional[str], optional): NUT-19 witness signature. Defaults to None.

        Raises:
            Exception: Validation of outputs failed.
            Exception: Quote not paid.
            Exception: Quote already issued.
            Exception: Quote expired.
            Exception: Amount to mint does not match quote amount.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        await self._verify_outputs(outputs)
        sum_amount_outputs = sum([b.amount for b in outputs])
        # we already know from _verify_outputs that all outputs have the same unit because they have the same keyset
        output_unit = self.keysets[outputs[0].id].unit

        quote = await self.get_mint_quote(quote_id)
        if quote.pending:
            raise TransactionError("Mint quote already pending.")
        if quote.issued:
            raise QuoteAlreadyIssuedError()
        if quote.state != MintQuoteState.paid:
            raise QuoteNotPaidError()

        previous_state = quote.state
        await self.db_write._set_mint_quote_pending(quote_id=quote_id)
        try:
            if not quote.unit == output_unit.name:
                raise TransactionError("quote unit does not match output unit")
            if not quote.amount == sum_amount_outputs:
                raise TransactionError("amount to mint does not match quote amount")
            if quote.expiry and quote.expiry < int(time.time()):
                raise TransactionError("quote expired")
            if not self._verify_mint_quote_witness(quote, outputs, signature):
                raise QuoteSignatureInvalidError()
            await self._store_blinded_messages(outputs, mint_id=quote_id)
            promises = await self._sign_blinded_messages(outputs)
        except Exception as e:
            await self.db_write._unset_mint_quote_pending(
                quote_id=quote_id, state=previous_state
            )
            raise e
        await self.db_write._unset_mint_quote_pending(
            quote_id=quote_id, state=MintQuoteState.issued
        )

        return promises

    async def mint_batch(
        self,
        payload: PostMintBatchRequest,
    ) -> List[BlindedSignature]:
        """Batch mint tokens.

        Args:
            payload (PostMintBatchRequest): Request payload containing quote IDs, outputs, and signatures.

        Raises:
            Exception: Validation of outputs failed.
            Exception: Quote not paid.
            Exception: Quote already issued.
            Exception: Amount to mint does not match quote amount.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        if not payload.quotes:
            raise TransactionError("batch must not be empty")

        if len(set(payload.quotes)) != len(payload.quotes):
            raise BatchDuplicateQuotesError()

        if payload.signatures and len(payload.signatures) != len(payload.quotes):
            raise TransactionError("signatures length must match quotes length")

        await self._verify_outputs(payload.outputs)
        # we already know from _verify_outputs that all outputs have the same unit because they have the same keyset
        output_unit = self.keysets[payload.outputs[0].id].unit
        sum_amount_outputs = sum([b.amount for b in payload.outputs])

        quotes: List[MintQuote] = []
        for quote_id in payload.quotes:
            quote = await self.get_mint_quote(quote_id)
            if not quote:
                raise TransactionError(f"quote {quote_id} not found")
            quotes.append(quote)

        # Check payment method consistency
        methods = set([q.method for q in quotes])
        if len(methods) > 1:
            raise TransactionError("all quotes must have the same method")

        # Check currency unit consistency
        units = set([q.unit for q in quotes])
        if len(units) > 1:
            raise TransactionError("all quotes must have the same unit")
        if units.pop() != output_unit.name:
            raise TransactionError("quote unit does not match output unit")

        for quote in quotes:
            if quote.pending:
                raise TransactionError("mint quote already pending")
            if quote.issued:
                raise QuoteAlreadyIssuedError()
            if quote.state != MintQuoteState.paid:
                raise QuoteNotPaidError()

        # Check amount balance
        if payload.quote_amounts:
            if len(payload.quote_amounts) != len(quotes):
                raise TransactionError("quote_amounts length must match quotes length")
            for i, quote in enumerate(quotes):
                if (
                    quote.method == "bolt11"
                    and payload.quote_amounts[i] != quote.amount
                ):
                    raise TransactionError(
                        f"quote amount {payload.quote_amounts[i]} does not match quote {quote.quote} amount {quote.amount}"
                    )
                if payload.quote_amounts[i] > quote.amount:
                    raise TransactionError(
                        f"quote amount {payload.quote_amounts[i]} exceeds quote {quote.quote} amount {quote.amount}"
                    )

        quote_amounts = payload.quote_amounts or [q.amount for q in quotes]
        if "bolt11" in methods:
            if sum(quote_amounts) != sum_amount_outputs:
                raise TransactionError(
                    "amount to mint does not match quote amounts sum"
                )
        else:
            if sum_amount_outputs > sum(quote_amounts):
                raise TransactionError("amount to mint exceeds quote amounts sum")

        # Signature validation (NUT-20)
        for i, quote in enumerate(quotes):
            sig = payload.signatures[i] if payload.signatures else None

            if not quote.pubkey and sig:
                raise QuoteSignatureInvalidError()

            # The spec says msg_to_sign = quote_id[i] || B_0 || B_1 || ... || B_(n-1)
            # This logic is inside self._verify_mint_quote_witness, let's reuse it.
            if not self._verify_mint_quote_witness(quote, payload.outputs, sig):
                raise QuoteSignatureInvalidError()

        # Set all quotes to pending
        quotes = await self.db_write._set_mint_quotes_pending(quote_ids=payload.quotes)

        try:
            for quote in quotes:
                if quote.expiry and quote.expiry < int(time.time()):
                    raise TransactionError("quote expired")

            # Store all blinded messages
            await self._store_blinded_messages(
                payload.outputs, mint_id=payload.quotes[0]
            )
            promises = await self._sign_blinded_messages(payload.outputs)

        except Exception as e:
            # Revert pending status
            await self.db_write._unset_mint_quotes_pending(
                quote_ids=payload.quotes, state=MintQuoteState.paid
            )
            raise e

        # Set all quotes to issued
        await self.db_write._unset_mint_quotes_pending(
            quote_ids=payload.quotes, state=MintQuoteState.issued
        )

        return promises
