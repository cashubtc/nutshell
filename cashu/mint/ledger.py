import asyncio
import base64
import time
from typing import Dict, List, Mapping, Optional, Tuple

import bolt11
from loguru import logger

from ..core.base import (
    DLEQ,
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    MeltQuoteState,
    Method,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
    ProofSpentState,
    ProofState,
    Unit,
)
from ..core.crypto import b_dhke
from ..core.crypto.aes import AESCipher
from ..core.crypto.keys import (
    derive_keyset_id,
    derive_pubkey,
    random_hash,
)
from ..core.crypto.secp import PrivateKey, PublicKey
from ..core.db import Connection, Database
from ..core.errors import (
    CashuError,
    KeysetError,
    KeysetNotFoundError,
    LightningError,
    NotAllowedError,
    QuoteNotPaidError,
    TransactionError,
)
from ..core.helpers import sum_proofs
from ..core.models import (
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMintQuoteRequest,
)
from ..core.settings import settings
from ..core.split import amount_split
from ..lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
)
from ..mint.crud import LedgerCrudSqlite
from .conditions import LedgerSpendingConditions
from .db.read import DbReadHelper
from .db.write import DbWriteHelper
from .events.events import LedgerEventManager
from .features import LedgerFeatures
from .tasks import LedgerTasks
from .verification import LedgerVerification


class Ledger(LedgerVerification, LedgerSpendingConditions, LedgerTasks, LedgerFeatures):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    keysets: Dict[str, MintKeyset] = {}
    events = LedgerEventManager()
    db_read: DbReadHelper
    invoice_listener_tasks: List[asyncio.Task] = []
    disable_melt: bool = False

    def __init__(
        self,
        db: Database,
        seed: str,
        backends: Mapping[Method, Mapping[Unit, LightningBackend]],
        seed_decryption_key: Optional[str] = None,
        derivation_path="",
        crud=LedgerCrudSqlite(),
    ):
        if not seed:
            raise Exception("seed not set")

        # decrypt seed if seed_decryption_key is set
        try:
            self.seed = (
                AESCipher(seed_decryption_key).decrypt(seed)
                if seed_decryption_key
                else seed
            )
        except Exception as e:
            raise Exception(
                f"Could not decrypt seed. Make sure that the seed is correct and the decryption key is set. {e}"
            )
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud
        self.backends = backends
        self.pubkey = derive_pubkey(self.seed)
        self.db_read = DbReadHelper(self.db, self.crud)
        self.db_write = DbWriteHelper(self.db, self.crud, self.events, self.db_read)

    # ------- STARTUP -------

    async def startup_ledger(self):
        await self._startup_ledger()
        await self._check_pending_proofs_and_melt_quotes()
        self.invoice_listener_tasks = await self.dispatch_listeners()

    async def _startup_ledger(self):
        await self.init_keysets()

        for derivation_path in settings.mint_derivation_path_list:
            await self.activate_keyset(derivation_path=derivation_path)

        for method in self.backends:
            for unit in self.backends[method]:
                logger.info(
                    f"Using {self.backends[method][unit].__class__.__name__} backend for"
                    f" method: '{method.name}' and unit: '{unit.name}'"
                )
                status = await self.backends[method][unit].status()
                if status.error_message:
                    logger.error(
                        "The backend for"
                        f" {self.backends[method][unit].__class__.__name__} isn't"
                        f" working properly: '{status.error_message}'"
                    )
                    exit(1)
                logger.info(f"Backend balance: {status.balance} {unit.name}")

        logger.info(f"Data dir: {settings.cashu_dir}")

    async def shutdown_ledger(self):
        await self.db.engine.dispose()
        for task in self.invoice_listener_tasks:
            task.cancel()

    async def _check_pending_proofs_and_melt_quotes(self):
        """Startup routine that checks all pending proofs for their melt state and either invalidates
        them for a successful melt or deletes them if the melt failed.
        """
        # get all pending melt quotes
        melt_quotes = await self.crud.get_all_melt_quotes_from_pending_proofs(
            db=self.db
        )
        if not melt_quotes:
            return
        logger.info("Checking pending melt quotes")
        for quote in melt_quotes:
            quote = await self.get_melt_quote(quote_id=quote.quote, purge_unknown=True)
            logger.info(f"Melt quote {quote.quote} state: {quote.state}")

    # ------- KEYS -------

    async def activate_keyset(
        self,
        *,
        derivation_path: str,
        seed: Optional[str] = None,
        version: Optional[str] = None,
        autosave=True,
    ) -> MintKeyset:
        """Load the keyset for a derivation path if it already exists. If not generate new one and store in the db.

        Args:
            derivation_path (_type_): Derivation path from which the keyset is generated.
            autosave (bool, optional): Store newly-generated keyset if not already in database. Defaults to True.

        Returns:
            MintKeyset: Keyset
        """
        if not derivation_path:
            raise Exception("derivation path not set")
        seed = seed or self.seed
        tmp_keyset_local = MintKeyset(
            seed=seed,
            derivation_path=derivation_path,
            version=version or settings.version,
        )
        logger.debug(
            f"Activating keyset for derivation path {derivation_path} with id"
            f" {tmp_keyset_local.id}."
        )
        # load the keyset from db
        logger.trace(f"crud: loading keyset for {derivation_path}")
        tmp_keysets_local: List[MintKeyset] = await self.crud.get_keyset(
            id=tmp_keyset_local.id, db=self.db
        )
        logger.trace(f"crud: loaded {len(tmp_keysets_local)} keysets")
        if tmp_keysets_local:
            # we have a keyset with this derivation path in the database
            keyset = tmp_keysets_local[0]
        else:
            # no keyset for this derivation path yet
            # we create a new keyset (keys will be generated at instantiation)
            keyset = MintKeyset(
                seed=seed or self.seed,
                derivation_path=derivation_path,
                version=version or settings.version,
                input_fee_ppk=settings.mint_input_fee_ppk,
            )
            logger.debug(f"Generated new keyset {keyset.id}.")
            if autosave:
                logger.debug(f"crud: storing new keyset {keyset.id}.")
                await self.crud.store_keyset(keyset=keyset, db=self.db)
                logger.trace(f"crud: stored new keyset {keyset.id}.")

        # activate this keyset
        keyset.active = True
        # load the new keyset in self.keysets
        self.keysets[keyset.id] = keyset

        logger.debug(f"Loaded keyset {keyset.id}")
        return keyset

    async def init_keysets(self, autosave: bool = True) -> None:
        """Initializes all keysets of the mint from the db. Loads all past keysets from db
        and generate their keys. Then activate the current keyset set by self.derivation_path.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
                not in the database yet. Will be passed to `self.activate_keyset` where it is
                generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db, the keys will be generated at instantiation
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)

        # add keysets from db to memory
        for k in tmp_keysets:
            self.keysets[k.id] = k

        logger.info(f"Loaded {len(self.keysets)} keysets from database.")

        # activate the current keyset set by self.derivation_path
        if self.derivation_path:
            self.keyset = await self.activate_keyset(
                derivation_path=self.derivation_path, autosave=autosave
            )
            logger.info(f"Current keyset: {self.keyset.id}")

        # check that we have a least one active keyset
        if not any([k.active for k in self.keysets.values()]):
            raise KeysetError("No active keyset found.")

        # DEPRECATION 0.16.1 – disable base64 keysets if hex equivalent exists
        if settings.mint_inactivate_base64_keysets:
            await self.inactivate_base64_keysets()

    async def inactivate_base64_keysets(self) -> None:
        """Inactivates all base64 keysets that have a hex equivalent."""
        for keyset in self.keysets.values():
            if not keyset.active or not keyset.public_keys:
                continue
            # test if the keyset id is a hex string, if not it's base64
            try:
                int(keyset.id, 16)
            except ValueError:
                # verify that it's base64
                try:
                    _ = base64.b64decode(keyset.id)
                except ValueError:
                    logger.error("Unexpected: keyset id is neither hex nor base64.")
                    continue

                # verify that we have a hex version of the same keyset by comparing public keys
                hex_keyset_id = derive_keyset_id(keys=keyset.public_keys)
                if hex_keyset_id not in [k.id for k in self.keysets.values()]:
                    logger.warning(
                        f"Keyset {keyset.id} is base64 but we don't have a hex version. Ignoring."
                    )
                    continue

                logger.warning(
                    f"Keyset {keyset.id} is base64 and has a hex counterpart, setting inactive."
                )
                keyset.active = False
                self.keysets[keyset.id] = keyset
                await self.crud.update_keyset(keyset=keyset, db=self.db)

    def get_keyset(self, keyset_id: Optional[str] = None) -> Dict[int, str]:
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets:
            raise KeysetNotFoundError()
        keyset = self.keysets[keyset_id] if keyset_id else self.keyset
        if not keyset.public_keys:
            raise KeysetError("no public keys for this keyset")
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}

    async def get_balance(self) -> int:
        """Returns the balance of the mint."""
        return await self.crud.get_balance(db=self.db)

    # ------- ECASH -------

    async def _invalidate_proofs(
        self,
        *,
        proofs: List[Proof],
        quote_id: Optional[str] = None,
        conn: Optional[Connection] = None,
    ) -> None:
        """Adds proofs to the set of spent proofs and stores them in the db.

        Args:
            proofs (List[Proof]): Proofs to add to known secret table.
            conn: (Optional[Connection], optional): Database connection to reuse. Will create a new one if not given. Defaults to None.
        """
        async with self.db.get_connection(conn) as conn:
            # store in db
            for p in proofs:
                logger.trace(f"Invalidating proof {p.Y}")
                await self.crud.invalidate_proof(
                    proof=p, db=self.db, quote_id=quote_id, conn=conn
                )
                await self.events.submit(
                    ProofState(
                        Y=p.Y, state=ProofSpentState.spent, witness=p.witness or None
                    )
                )

    async def _generate_change_promises(
        self,
        fee_provided: int,
        fee_paid: int,
        outputs: Optional[List[BlindedMessage]],
        keyset: Optional[MintKeyset] = None,
    ) -> List[BlindedSignature]:
        """Generates a set of new promises (blinded signatures) from a set of blank outputs
        (outputs with no or ignored amount) by looking at the difference between the Lightning
        fee reserve provided by the wallet and the actual Lightning fee paid by the mint.

        If there is a positive difference, produces maximum `n_return_outputs` new outputs
        with values close or equal to the fee difference. If the given number of `outputs` matches
        the equation defined in NUT-08, we can be sure to return the overpaid fee perfectly.
        Otherwise, a smaller amount will be returned.

        Args:
            input_amount (int): Amount of the proofs provided by the client.
            output_amount (int): Amount of the melt request to be paid.
            output_fee_paid (int): Actually paid melt network fees.
            outputs (Optional[List[BlindedMessage]]): Outputs to sign for returning the overpaid fees.

        Raises:
            Exception: Output validation failed.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        # we make sure that the fee is positive
        overpaid_fee = fee_provided - fee_paid

        if overpaid_fee == 0 or outputs is None:
            return []

        logger.debug(
            f"Lightning fee was: {fee_paid}. User provided: {fee_provided}. "
            f"Returning difference: {overpaid_fee}."
        )

        return_amounts = amount_split(overpaid_fee)

        # We return at most as many outputs as were provided or as many as are
        # required to pay back the overpaid fee.
        n_return_outputs = min(len(outputs), len(return_amounts))

        # we only need as many outputs as we have change to return
        outputs = outputs[:n_return_outputs]

        # we sort the return_amounts in descending order so we only
        # take the largest values in the next step
        return_amounts_sorted = sorted(return_amounts, reverse=True)
        # we need to imprint these amounts into the blanket outputs
        for i in range(len(outputs)):
            outputs[i].amount = return_amounts_sorted[i]  # type: ignore
        if not self._verify_no_duplicate_outputs(outputs):
            raise TransactionError("duplicate promises.")
        return_promises = await self._generate_promises(outputs, keyset)
        return return_promises

    # ------- TRANSACTIONS -------

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
        if settings.mint_max_peg_in and quote_request.amount > settings.mint_max_peg_in:
            raise NotAllowedError(
                f"Maximum mint amount is {settings.mint_max_peg_in} sat."
            )
        if settings.mint_peg_out_only:
            raise NotAllowedError("Mint does not allow minting new tokens.")

        unit, method = self._verify_and_get_unit_method(
            quote_request.unit, Method.bolt11.name
        )

        if (
            quote_request.description
            and not self.backends[method][unit].supports_description
        ):
            raise NotAllowedError("Backend does not support descriptions.")

        if settings.mint_max_balance:
            balance = await self.get_balance()
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

        expiry = None
        if invoice_obj.expiry is not None:
            expiry = invoice_obj.date + invoice_obj.expiry

        quote = MintQuote(
            quote=random_hash(),
            method=method.name,
            request=request,
            checking_id=invoice_response.checking_id,
            unit=quote_request.unit,
            amount=quote_request.amount,
            state=MintQuoteState.unpaid,
            created_time=int(time.time()),
            expiry=expiry,
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
            logger.trace(f"Lightning: checking invoice {quote.checking_id}")
            status: PaymentStatus = await self.backends[method][
                unit
            ].get_invoice_status(quote.checking_id)
            if status.settled:
                # change state to paid in one transaction, it could have been marked paid
                # by the invoice listener in the mean time
                async with self.db.get_connection(
                    lock_table="mint_quotes",
                    lock_select_statement=f"quote='{quote_id}'",
                ) as conn:
                    quote = await self.crud.get_mint_quote(
                        quote_id=quote_id, db=self.db, conn=conn
                    )
                    if not quote:
                        raise Exception("quote not found")
                    if quote.unpaid:
                        logger.trace(f"Setting quote {quote_id} as paid")
                        quote.state = MintQuoteState.paid
                        quote.paid_time = int(time.time())
                        await self.crud.update_mint_quote(
                            quote=quote, db=self.db, conn=conn
                        )
                        await self.events.submit(quote)

        return quote

    async def mint(
        self,
        *,
        outputs: List[BlindedMessage],
        quote_id: str,
    ) -> List[BlindedSignature]:
        """Mints new coins if quote with `quote_id` was paid. Ingest blind messages `outputs` and returns blind signatures `promises`.

        Args:
            outputs (List[BlindedMessage]): Outputs (blinded messages) to sign.
            quote_id (str): Mint quote id.
            keyset (Optional[MintKeyset], optional): Keyset to use. If not provided, uses active keyset. Defaults to None.

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
            raise TransactionError("Mint quote already issued.")
        if not quote.paid:
            raise QuoteNotPaidError()
        previous_state = quote.state
        await self.db_write._set_mint_quote_pending(quote_id=quote_id)
        try:
            if not quote.unit == output_unit.name:
                raise TransactionError("quote unit does not match output unit")
            if not quote.amount == sum_amount_outputs:
                raise TransactionError("amount to mint does not match quote amount")
            if quote.expiry and quote.expiry > int(time.time()):
                raise TransactionError("quote expired")
            promises = await self._generate_promises(outputs)
        except Exception as e:
            await self.db_write._unset_mint_quote_pending(
                quote_id=quote_id, state=previous_state
            )
            raise e
        await self.db_write._unset_mint_quote_pending(
            quote_id=quote_id, state=MintQuoteState.issued
        )

        return promises

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
        if melt_quote.is_mpp and melt_quote.mpp_amount != payment_quote.amount.amount:
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
            payment_quote = self.create_internal_melt_quote(mint_quote, melt_quote)
        else:
            # not internal
            # verify that the backend supports mpp if the quote request has an amount
            if melt_quote.is_mpp and not self.backends[method][unit].supports_mpp:
                raise TransactionError("backend does not support mpp")
            # get payment quote by backend
            payment_quote = await self.backends[method][unit].get_payment_quote(
                melt_quote=melt_quote
            )

        self.validate_payment_quote(melt_quote, payment_quote)

        # verify that the amount of the proofs is not larger than the maximum allowed
        if (
            settings.mint_max_peg_out
            and payment_quote.amount.to(unit).amount > settings.mint_max_peg_out
        ):
            raise NotAllowedError(
                f"Maximum melt amount is {settings.mint_max_peg_out} sat."
            )

        # We assume that the request is a bolt11 invoice, this works since we
        # support only the bol11 method for now.
        invoice_obj = bolt11.decode(melt_quote.request)
        if not invoice_obj.amount_msat:
            raise TransactionError("invoice has no amount.")
        # we set the expiry of this quote to the expiry of the bolt11 invoice
        expiry = None
        if invoice_obj.expiry is not None:
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
            created_time=int(time.time()),
            expiry=expiry,
        )
        await self.crud.store_melt_quote(quote=quote, db=self.db)
        await self.events.submit(quote)

        return PostMeltQuoteResponse(
            quote=quote.quote,
            amount=quote.amount,
            fee_reserve=quote.fee_reserve,
            paid=quote.paid,  # deprecated
            state=quote.state.value,
            expiry=quote.expiry,
        )

    async def get_melt_quote(self, quote_id: str, purge_unknown=False) -> MeltQuote:
        """Returns a melt quote.

        If the melt quote is pending, checks status of the payment with the backend.
            - If settled, sets the quote as paid and invalidates pending proofs (commit).
            - If failed, sets the quote as unpaid and unsets pending proofs (rollback).
            - If purge_unknown is set, do the same for unknown states as for failed states.

        Args:
            quote_id (str): ID of the melt quote.
            purge_unknown (bool, optional): Rollback unknown payment states to unpaid. Defaults to False.

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
                await self.crud.update_melt_quote(quote=melt_quote, db=self.db)
                await self.events.submit(melt_quote)
                pending_proofs = await self.crud.get_pending_proofs_for_quote(
                    quote_id=quote_id, db=self.db
                )
                await self._invalidate_proofs(proofs=pending_proofs, quote_id=quote_id)
                await self.db_write._unset_proofs_pending(pending_proofs)
            if status.failed or (purge_unknown and status.unknown):
                logger.debug(f"Setting quote {quote_id} as unpaid")
                melt_quote.state = MeltQuoteState.unpaid
                await self.crud.update_melt_quote(quote=melt_quote, db=self.db)
                await self.events.submit(melt_quote)
                pending_proofs = await self.crud.get_pending_proofs_for_quote(
                    quote_id=quote_id, db=self.db
                )
                await self.db_write._unset_proofs_pending(pending_proofs)

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
            Tuple[str, List[BlindedMessage]]: Proof of payment and signed outputs for returning overpaid fees to wallet.
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

        # make sure that the outputs (for fee return) are in the same unit as the quote
        if outputs:
            # _verify_outputs checks if all outputs have the same unit
            await self._verify_outputs(outputs, skip_amount_check=True)
            outputs_unit = self.keysets[outputs[0].id].unit
            if not melt_quote.unit == outputs_unit.name:
                raise TransactionError(
                    f"output unit {outputs_unit.name} does not match quote unit {melt_quote.unit}"
                )

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
        # verify that the amount of the proofs is not larger than the maximum allowed
        if settings.mint_max_peg_out and total_provided > settings.mint_max_peg_out:
            raise NotAllowedError(
                f"Maximum melt amount is {settings.mint_max_peg_out} sat."
            )
        # verify inputs and their spending conditions
        # note, we do not verify outputs here, as they are only used for returning overpaid fees
        # We must have called _verify_outputs here already! (see above)
        await self.verify_inputs_and_outputs(proofs=proofs)

        # set proofs to pending to avoid race conditions
        await self.db_write._verify_spent_proofs_and_set_pending(
            proofs, quote_id=melt_quote.quote
        )
        previous_state = melt_quote.state
        melt_quote = await self.db_write._set_melt_quote_pending(melt_quote)

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
                            await self.db_write._unset_proofs_pending(proofs)
                            await self.db_write._unset_melt_quote_pending(
                                quote=melt_quote, state=previous_state
                            )
                            if status.error_message:
                                logger.error(
                                    f"Status check error: {status.error_message}"
                                )
                            raise LightningError(
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
        await self._invalidate_proofs(proofs=proofs, quote_id=melt_quote.quote)
        await self.db_write._unset_proofs_pending(proofs)

        # prepare change to compensate wallet for overpaid fees
        return_promises: List[BlindedSignature] = []
        if outputs:
            return_promises = await self._generate_change_promises(
                fee_provided=fee_reserve_provided,
                fee_paid=melt_quote.fee_paid,
                outputs=outputs,
                keyset=self.keysets[outputs[0].id],
            )

        melt_quote.change = return_promises

        await self.crud.update_melt_quote(quote=melt_quote, db=self.db)
        await self.events.submit(melt_quote)

        return PostMeltQuoteResponse.from_melt_quote(melt_quote)

    async def swap(
        self,
        *,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
    ):
        """Consumes proofs and prepares new promises based on the amount swap. Used for swapping tokens
        Before sending or for redeeming tokens for new ones that have been received by another wallet.

        Args:
            proofs (List[Proof]): Proofs to be invalidated for the swap.
            outputs (List[BlindedMessage]): New outputs that should be signed in return.
            keyset (Optional[MintKeyset], optional): Keyset to use. Uses default keyset if not given. Defaults to None.

        Raises:
            Exception: Validation of proofs or outputs failed

        Returns:
            List[BlindedSignature]: New promises (signatures) for the outputs.
        """
        logger.trace("swap called")
        # verify spending inputs, outputs, and spending conditions
        await self.verify_inputs_and_outputs(proofs=proofs, outputs=outputs)
        await self.db_write._verify_spent_proofs_and_set_pending(proofs)
        try:
            async with self.db.get_connection(lock_table="proofs_pending") as conn:
                await self._invalidate_proofs(proofs=proofs, conn=conn)
                promises = await self._generate_promises(outputs, keyset, conn)
        except Exception as e:
            logger.trace(f"swap failed: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self.db_write._unset_proofs_pending(proofs)

        logger.trace("swap successful")
        return promises

    async def restore(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        signatures: List[BlindedSignature] = []
        return_outputs: List[BlindedMessage] = []
        async with self.db.get_connection() as conn:
            for output in outputs:
                logger.trace(f"looking for promise: {output}")
                promise = await self.crud.get_promise(
                    b_=output.B_, db=self.db, conn=conn
                )
                if promise is not None:
                    signatures.append(promise)
                    return_outputs.append(output)
                    logger.trace(f"promise found: {promise}")
        return return_outputs, signatures

    # ------- BLIND SIGNATURES -------

    async def _generate_promises(
        self,
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
        conn: Optional[Connection] = None,
    ) -> list[BlindedSignature]:
        """Generates a promises (Blind signatures) for given amount and returns a pair (amount, C').

        Important: When a promises is once created it should be considered issued to the user since the user
        will always be able to restore promises later through the backup restore endpoint. That means that additional
        checks in the code that might decide not to return these promises should be avoided once this function is
        called. Only call this function if the transaction is fully validated!

        Args:
            B_s (List[BlindedMessage]): Blinded secret (point on curve)
            keyset (Optional[MintKeyset], optional): Which keyset to use. Private keys will be taken from this keyset.
                If not given will use the keyset of the first output. Defaults to None.
            conn: (Optional[Connection], optional): Database connection to reuse. Will create a new one if not given. Defaults to None.
        Returns:
            list[BlindedSignature]: Generated BlindedSignatures.
        """
        promises: List[
            Tuple[str, PublicKey, int, PublicKey, PrivateKey, PrivateKey]
        ] = []
        for output in outputs:
            B_ = PublicKey(bytes.fromhex(output.B_), raw=True)
            keyset = keyset or self.keysets[output.id]
            if output.id not in self.keysets:
                raise TransactionError(f"keyset {output.id} not found")
            if output.id != keyset.id:
                raise TransactionError("keyset id does not match output id")
            if not keyset.active:
                raise TransactionError("keyset is not active")
            keyset_id = output.id
            logger.trace(f"Generating promise with keyset {keyset_id}.")
            private_key_amount = keyset.private_keys[output.amount]
            C_, e, s = b_dhke.step2_bob(B_, private_key_amount)
            promises.append((keyset_id, B_, output.amount, C_, e, s))

        keyset = keyset or self.keyset

        signatures = []
        async with self.db.get_connection(conn) as conn:
            for promise in promises:
                keyset_id, B_, amount, C_, e, s = promise
                logger.trace(f"crud: _generate_promise storing promise for {amount}")
                await self.crud.store_promise(
                    amount=amount,
                    id=keyset_id,
                    b_=B_.serialize().hex(),
                    c_=C_.serialize().hex(),
                    e=e.serialize(),
                    s=s.serialize(),
                    db=self.db,
                    conn=conn,
                )
                logger.trace(f"crud: _generate_promise stored promise for {amount}")
                signature = BlindedSignature(
                    id=keyset_id,
                    amount=amount,
                    C_=C_.serialize().hex(),
                    dleq=DLEQ(e=e.serialize(), s=s.serialize()),
                )
                signatures.append(signature)
            return signatures
