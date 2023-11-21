import asyncio
import copy
from typing import Dict, List, Mapping, Optional, Set, Tuple

import bolt11
from loguru import logger

from ..core.base import (
    DLEQ,
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    Method,
    MintKeyset,
    MintQuote,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMintQuoteRequest,
    Proof,
    Unit,
)
from ..core.crypto import b_dhke
from ..core.crypto.keys import derive_keyset_id_deprecated, derive_pubkey, random_hash
from ..core.crypto.secp import PublicKey
from ..core.db import Connection, Database
from ..core.errors import (
    KeysetError,
    KeysetNotFoundError,
    LightningError,
    NotAllowedError,
    TransactionError,
)
from ..core.helpers import sum_proofs
from ..core.settings import settings
from ..core.split import amount_split
from ..lightning.base import (
    InvoiceResponse,
    LightningBackend,
    PaymentQuoteResponse,
    PaymentStatus,
)
from ..mint.crud import LedgerCrudSqlite
from .conditions import LedgerSpendingConditions
from .verification import LedgerVerification


class Ledger(LedgerVerification, LedgerSpendingConditions):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    locks: Dict[str, asyncio.Lock] = {}  # holds multiprocessing locks
    proofs_pending_lock: asyncio.Lock = (
        asyncio.Lock()
    )  # holds locks for proofs_pending database
    keysets: Dict[str, MintKeyset] = {}

    def __init__(
        self,
        db: Database,
        seed: str,
        backends: Mapping[Method, Mapping[Unit, LightningBackend]],
        derivation_path="",
        crud=LedgerCrudSqlite(),
    ):
        self.secrets_used: Set[str] = set()
        self.master_key = seed
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud
        self.backends = backends
        self.pubkey = derive_pubkey(self.master_key)

    # ------- KEYS -------

    async def activate_keyset(self, derivation_path, autosave=True) -> MintKeyset:
        """Load the keyset for a derivation path if it already exists. If not generate new one and store in the db.

        Args:
            derivation_path (_type_): Derivation path from which the keyset is generated.
            autosave (bool, optional): Store newly-generated keyset if not already in database. Defaults to True.

        Returns:
            MintKeyset: Keyset
        """
        logger.debug(f"Activating keyset for derivation path {derivation_path}")
        # load the keyset from db
        logger.trace(f"crud: loading keyset for {derivation_path}")
        tmp_keyset_local: List[MintKeyset] = await self.crud.get_keyset(
            derivation_path=derivation_path, db=self.db
        )
        logger.trace(f"crud: loaded {len(tmp_keyset_local)} keysets")
        if tmp_keyset_local:
            # we have a keyset with this derivation path in the database
            keyset = tmp_keyset_local[0]
            # we keys are not stored in the database but only their derivation path
            # so we might need to generate the keys for keysets loaded from the database
            if not len(keyset.private_keys):
                keyset.generate_keys()

        else:
            logger.trace(f"crud: no keyset for {derivation_path}")
            # no keyset for this derivation path yet
            # we create a new keyset (keys will be generated at instantiation)
            keyset = MintKeyset(
                seed=self.master_key,
                derivation_path=derivation_path,
                version=settings.version,
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

    async def init_keysets(self, autosave=True) -> None:
        """Initializes all keysets of the mint from the db. Loads all past keysets from db
        and generate their keys. Then load the current keyset.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
            not in the database yet. Will be passed to `self.activate_keyset` where it is
            generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)
        logger.debug(
            f"Loaded {len(tmp_keysets)} keysets from database. Generating keys..."
        )
        # add keysets from db to current keysets
        for k in tmp_keysets:
            if k.id and k.id not in self.keysets:
                self.keysets[k.id] = k

        # generate keys for all keysets in the database
        for _, v in self.keysets.items():
            # we already generated the keys for this keyset
            if v.id and v.public_keys and len(v.public_keys):
                continue
            logger.trace(f"Generating keys for keyset {v.id}")
            v.seed = self.master_key
            v.generate_keys()

        logger.info(f"Initialized {len(self.keysets)} keysets from the database.")

        # activate the current keyset set by self.derivation_path
        self.keyset = await self.activate_keyset(self.derivation_path, autosave)
        logger.info(
            "Activated keysets from database:"
            f" {[f'{k} ({v.unit.name})' for k, v in self.keysets.items()]}"
        )
        logger.info(f"Current keyset: {self.keyset.id}")

        # check that we have a least one active keyset
        assert any([k.active for k in self.keysets.values()]), "No active keyset found."

        # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
        # we duplicate new keysets and compute their new keyset id
        for _, keyset in copy.copy(self.keysets).items():
            # NOTE: duplicate all keys for now
            if keyset.version_tuple < (0, 15) or True:
                deprecated_keyset_with_new_id = copy.copy(keyset)
                deprecated_id = deprecated_keyset_with_new_id.id
                assert deprecated_keyset_with_new_id.public_keys
                deprecated_keyset_with_new_id.id = derive_keyset_id_deprecated(
                    deprecated_keyset_with_new_id.public_keys
                )
                self.keysets[deprecated_keyset_with_new_id.id] = (
                    deprecated_keyset_with_new_id
                )
                logger.warning(
                    f"Duplicated deprecated keyset {deprecated_id} with new id"
                    f" {deprecated_keyset_with_new_id.id}."
                )
        # END BACKWARDS COMPATIBILITY < 0.15.0

    def get_keyset(self, keyset_id: Optional[str] = None) -> Dict[int, str]:
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets:
            raise KeysetNotFoundError()
        keyset = self.keysets[keyset_id] if keyset_id else self.keyset
        assert keyset.public_keys, KeysetError("no public keys for this keyset")
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}

    # ------- ECASH -------

    async def _invalidate_proofs(self, proofs: List[Proof]) -> None:
        """Adds secrets of proofs to the list of known secrets and stores them in the db.
        Removes proofs from pending table. This is executed if the ecash has been redeemed.

        Args:
            proofs (List[Proof]): Proofs to add to known secret table.
        """
        # Mark proofs as used and prepare new promises
        secrets = set([p.secret for p in proofs])
        self.secrets_used |= secrets
        # store in db
        for p in proofs:
            await self.crud.invalidate_proof(proof=p, db=self.db)

    async def _generate_change_promises(
        self,
        input_amount: int,
        output_amount: int,
        output_fee_paid: int,
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
        user_fee_paid = input_amount - output_amount
        overpaid_fee = user_fee_paid - output_fee_paid
        logger.debug(
            f"Lightning fee was: {output_fee_paid}. User paid: {overpaid_fee}. "
            f"Returning difference: {overpaid_fee}."
        )

        if overpaid_fee > 0 and outputs is not None:
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
        else:
            return []

    # ------- TRANSACTIONS -------

    async def mint_quote(self, quote_request: PostMintQuoteRequest) -> MintQuote:
        """Returns Lightning invoice and stores it in the db.

        Args:
            amount (int): Amount of the mint request in Satoshis.

        Raises:
            Exception: Invoice creation failed.

        Returns:
            Tuple[str, str]: Bolt11 invoice and a id (for looking it up later)
        """
        logger.trace("called request_mint")
        if settings.mint_max_peg_in and quote_request.amount > settings.mint_max_peg_in:
            raise NotAllowedError(
                f"Maximum mint amount is {settings.mint_max_peg_in} sat."
            )
        if settings.mint_peg_out_only:
            raise NotAllowedError("Mint does not allow minting new tokens.")
        unit = Unit[quote_request.unit]
        method = Method["bolt11"]

        logger.trace(f"requesting invoice for {unit.str(quote_request.amount)}")
        invoice_response: InvoiceResponse = await self.backends[method][
            unit
        ].create_invoice(Amount(unit=unit, amount=quote_request.amount))
        logger.trace(
            f"got invoice {invoice_response.payment_request} with check id"
            f" {invoice_response.checking_id}"
        )

        assert (
            invoice_response.payment_request and invoice_response.checking_id
        ), LightningError("could not fetch bolt11 payment request from backend")

        quote = MintQuote(
            quote=random_hash(),
            method="bolt11",
            request=invoice_response.payment_request,
            checking_id=invoice_response.checking_id,
            unit=quote_request.unit,
            amount=quote_request.amount,
            issued=False,
            paid=False,
        )
        await self.crud.store_mint_quote(
            quote=quote,
            db=self.db,
        )
        return quote

    async def mint(
        self,
        *,
        outputs: List[BlindedMessage],
        quote_id: str,
        keyset: Optional[MintKeyset] = None,
    ) -> List[BlindedSignature]:
        """Mints new coins if payment `id` was made. Ingest blind messages `outputs` and returns blind signatures `promises`.

        Args:
            outputs (List[BlindedMessage]): Outputs (blinded messages) to sign.
            quote (str): Quote of mint payment. Defaults to None.
            keyset (Optional[MintKeyset], optional): Keyset to use. If not provided, uses active keyset. Defaults to None.

        Raises:
            Exception: Lightning invoice is not paid.
            Exception: Lightning is turned on but no payment hash is provided.
            Exception: Something went wrong with the invoice check.
            Exception: Amount too large.

        Returns:
            List[BlindedSignature]: Signatures on the outputs.
        """
        logger.trace("called mint")
        self._verify_outputs(outputs)
        sum_amount_outputs = sum([b.amount for b in outputs])

        self.locks[quote_id] = (
            self.locks.get(quote_id) or asyncio.Lock()
        )  # create a new lock if it doesn't exist
        async with self.locks[quote_id]:
            quote = await self.crud.get_mint_quote(quote_id=quote_id, db=self.db)
            assert quote, "quote not found"
            assert not quote.issued, "quote already issued"
            assert (
                quote.amount == sum_amount_outputs
            ), "amount to mint does not match quote amount"

            assert quote.method == "bolt11", "only bolt11 supported"
            unit = Unit[quote.unit]
            method = Method["bolt11"]
            if not quote.paid:
                logger.debug(f"Lightning: checking invoice {quote.checking_id}")
                status: PaymentStatus = await self.backends[method][
                    unit
                ].get_invoice_status(quote.checking_id)
                assert status.paid, "invoice not paid"
                await self.crud.update_mint_quote_paid(
                    quote_id=quote_id, paid=True, db=self.db
                )

            logger.trace(f"crud: setting invoice {id} as issued")
            await self.crud.update_mint_quote_issued(
                quote_id=quote_id, issued=True, db=self.db
            )
        del self.locks[quote_id]

        promises = await self._generate_promises(outputs, keyset)
        logger.trace("generated promises")
        return promises

    async def melt_quote(
        self, melt_quote: PostMeltQuoteRequest
    ) -> PostMeltQuoteResponse:
        unit = Unit[melt_quote.unit]
        method = Method["bolt11"]
        invoice_obj = bolt11.decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        payment_quote: PaymentQuoteResponse = await self.backends[method][
            unit
        ].get_payment_quote(melt_quote.request)

        quote = MeltQuote(
            quote=random_hash(),
            method="bolt11",  # TODO: remove unnecessary fields
            request=melt_quote.request,  # TODO: remove unnecessary fields
            checking_id=payment_quote.checking_id,
            unit=melt_quote.unit,
            amount=payment_quote.amount.to(unit).amount,
            paid=False,
            fee_reserve=payment_quote.fee.to(unit).amount,
        )
        await self.crud.store_melt_quote(quote=quote, db=self.db)
        return PostMeltQuoteResponse(
            quote=quote.quote,
            amount=quote.amount,
            fee_reserve=quote.fee_reserve,
        )

    async def melt(
        self,
        *,
        proofs: List[Proof],
        quote: str,
        outputs: Optional[List[BlindedMessage]] = None,
        keyset: Optional[MintKeyset] = None,
    ) -> Tuple[str, List[BlindedSignature]]:
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
        # verify quote
        melt_quote = await self.crud.get_melt_quote(quote_id=quote, db=self.db)
        assert melt_quote, "quote not found"
        assert melt_quote.method == "bolt11", "only bolt11 supported"

        method = Method["bolt11"]
        unit = Unit[melt_quote.unit]
        # make sure that the outputs (for fee return) are in the same unit as the quote
        if outputs:
            assert outputs[0].id, "output id not set"
            outputs_unit = self.keysets[outputs[0].id].unit
            assert outputs_unit
            assert melt_quote.unit == outputs_unit.name, (
                f"output unit {outputs_unit.name} does not match quote unit"
                f" {melt_quote.unit}"
            )
        assert not melt_quote.paid, "melt quote already paid"
        bolt11_request = melt_quote.request
        total_provided = sum_proofs(proofs)
        total_needed = melt_quote.amount + (melt_quote.fee_reserve or 0)
        assert total_provided >= total_needed, (
            f"provided proofs not enough. Provided: {total_provided}, needed:"
            f" {total_needed}"
        )
        if settings.mint_max_peg_out and total_provided > settings.mint_max_peg_out:
            raise NotAllowedError(
                f"Maximum melt amount is {settings.mint_max_peg_out} sat."
            )
        # verify inputs and their spending conditions
        await self.verify_inputs_and_outputs(proofs=proofs)

        # set proofs to pending to avoid race conditions
        await self._set_proofs_pending(proofs)

        try:
            # verify amounts from bolt11 invoice
            # invoice_obj = bolt11.decode(bolt11_request)
            # assert invoice_obj.amount_msat, "invoice has no amount."
            # invoice_amount = math.ceil(invoice_obj.amount_msat / 1000)

            # first we check if there is a mint quote with the same payment request
            # so that we can handle the transaction internally without lightning
            fees_paid, payment_proof = 0, ""
            mint_quote = await self.crud.get_mint_quote_by_checking_id(
                checking_id=melt_quote.checking_id, db=self.db
            )
            if mint_quote:
                # we settle the transaction internally
                # assert Amount(unit, mint_quote.amount).to() == invoice_amount, "amounts do not match"
                assert (
                    bolt11_request == mint_quote.request
                ), "bolt11 requests do not match"
                assert mint_quote.unit == melt_quote.unit, "units do not match"
                assert mint_quote.method == melt_quote.method, "methods do not match"
                assert not mint_quote.paid, "mint quote already paid"
                assert not mint_quote.issued, "mint quote already issued"
                logger.info(
                    f"Settling bolt11 payment internally: {melt_quote.quote} ->"
                    f" {mint_quote.quote} ({melt_quote.amount} {melt_quote.unit})"
                )
                # we handle this transaction internally
                await self.crud.update_mint_quote_paid(
                    quote_id=mint_quote.quote, paid=True, db=self.db
                )

            else:
                # TODO: Check if melt_quote.fee_reserve is always the correct unit!
                logger.debug(f"Lightning: pay invoice {bolt11_request}")
                payment = await self.backends[method][unit].pay_invoice(
                    melt_quote, melt_quote.fee_reserve * 1000
                )
                logger.trace("paid lightning invoice")

                logger.debug(
                    f"Melt status: {payment.ok}: preimage: {payment.preimage},"
                    f" fee: {payment.fee.str() if payment.fee else 0}"
                )
                if not payment.ok:
                    raise LightningError("Lightning payment unsuccessful.")
                if payment.fee:
                    fees_paid = payment.fee.to(to_unit=unit, round="up").amount
                if payment.preimage:
                    payment_proof = payment.preimage

            # melt successful, invalidate proofs
            await self._invalidate_proofs(proofs)

            # set quote as paid
            await self.crud.update_melt_quote(quote_id=quote, paid=True, db=self.db)

            # prepare change to compensate wallet for overpaid fees
            return_promises: List[BlindedSignature] = []
            if outputs and fees_paid is not None:
                assert outputs[0].id, "output id not set"
                return_promises = await self._generate_change_promises(
                    input_amount=total_provided,
                    output_amount=melt_quote.amount,
                    output_fee_paid=fees_paid,
                    outputs=outputs,
                    keyset=self.keysets[outputs[0].id],
                )

        except Exception as e:
            logger.trace(f"exception: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        return payment_proof or "", return_promises

    async def split(
        self,
        *,
        proofs: List[Proof],
        outputs: List[BlindedMessage],
        keyset: Optional[MintKeyset] = None,
    ):
        """Consumes proofs and prepares new promises based on the amount split. Used for splitting tokens
        Before sending or for redeeming tokens for new ones that have been received by another wallet.

        Args:
            proofs (List[Proof]): Proofs to be invalidated for the split.
            amount (int): Amount at which the split should happen.
            outputs (List[BlindedMessage]): New outputs that should be signed in return.
            keyset (Optional[MintKeyset], optional): Keyset to use. Uses default keyset if not given. Defaults to None.

        Raises:
            Exception: Validation of proofs or outputs failed

        Returns:
            Tuple[List[BlindSignature],List[BlindSignature]]: Promises on both sides of the split.
        """
        logger.trace("split called")

        await self._set_proofs_pending(proofs)
        try:
            # verify spending inputs, outputs, and spending conditions
            await self.verify_inputs_and_outputs(proofs=proofs, outputs=outputs)
            # Mark proofs as used and prepare new promises
            await self._invalidate_proofs(proofs)
        except Exception as e:
            logger.trace(f"split failed: {e}")
            raise e
        finally:
            # delete proofs from pending list
            await self._unset_proofs_pending(proofs)

        promises = await self._generate_promises(outputs, keyset)

        # verify amounts in produced promises
        self._verify_equation_balanced(proofs, promises)

        logger.trace("split successful")
        return promises

    async def restore(
        self, outputs: List[BlindedMessage]
    ) -> Tuple[List[BlindedMessage], List[BlindedSignature]]:
        promises: List[BlindedSignature] = []
        return_outputs: List[BlindedMessage] = []
        async with self.db.connect() as conn:
            for output in outputs:
                logger.trace(f"looking for promise: {output}")
                promise = await self.crud.get_promise(
                    B_=output.B_, db=self.db, conn=conn
                )
                if promise is not None:
                    # BEGIN backwards compatibility mints pre `m007_proofs_and_promises_store_id`
                    # add keyset id to promise if not present only if the current keyset
                    # is the only one ever used
                    if not promise.id and len(self.keysets) == 1:
                        promise.id = self.keyset.id
                    # END backwards compatibility
                    promises.append(promise)
                    return_outputs.append(output)
                    logger.trace(f"promise found: {promise}")
        return return_outputs, promises

    # ------- BLIND SIGNATURES -------

    async def _generate_promises(
        self, outputs: List[BlindedMessage], keyset: Optional[MintKeyset] = None
    ) -> list[BlindedSignature]:
        """Generates promises that sum to the given amount.

        Args:
            B_s (List[BlindedMessage]): _description_
            keyset (Optional[MintKeyset], optional): _description_. Defaults to None.

        Returns:
            list[BlindedSignature]: _description_
        """
        return [await self._generate_promise(o, keyset) for o in outputs]

    async def _generate_promise(
        self,
        output: BlindedMessage,
        keyset: Optional[MintKeyset] = None,
    ) -> BlindedSignature:
        """Generates a promise (Blind signature) for given amount and returns a pair (amount, C').

        Args:
            output (BlindedMessage): output to generate blind signature for
            B_ (PublicKey): Blinded secret (point on curve)
            keyset (Optional[MintKeyset], optional): Which keyset to use. Private keys will be taken from this keyset. Defaults to None.

        Returns:
            BlindedSignature: Generated promise.
        """
        B_ = PublicKey(bytes.fromhex(output.B_), raw=True)
        assert output.id, "output id not set"
        keyset = keyset if keyset else self.keysets[output.id]

        assert output.id in self.keysets, f"keyset {output.id} not found"
        assert output.id == keyset.id, "keyset id does not match output id"
        assert keyset.active, "keyset is not active"

        logger.trace(f"Generating promise with keyset {keyset.id}.")
        private_key_amount = keyset.private_keys[output.amount]
        C_, e, s = b_dhke.step2_bob(B_, private_key_amount)
        logger.trace(f"crud: _generate_promise storing promise for {output.amount}")
        await self.crud.store_promise(
            amount=output.amount,
            id=output.id,
            B_=B_.serialize().hex(),
            C_=C_.serialize().hex(),
            e=e.serialize(),
            s=s.serialize(),
            db=self.db,
        )
        logger.trace(f"crud: _generate_promise stored promise for {output.amount}")
        return BlindedSignature(
            id=output.id,
            amount=output.amount,
            C_=C_.serialize().hex(),
            dleq=DLEQ(e=e.serialize(), s=s.serialize()),
        )

    # ------- PROOFS -------

    async def load_used_proofs(self) -> None:
        """Load all used proofs from database."""
        logger.trace("crud: loading used proofs")
        secrets_used = await self.crud.get_secrets_used(db=self.db)
        if secrets_used:
            logger.trace(f"crud: loaded {len(secrets_used)} used proofs")
            self.secrets_used = set(secrets_used)

    def _check_spendable(self, proof: Proof) -> bool:
        """Checks whether the proof was already spent."""
        return proof.secret not in self.secrets_used

    async def _check_pending(self, proofs: List[Proof]) -> List[bool]:
        """Checks whether the proof is still pending."""
        proofs_pending = await self.crud.get_proofs_pending(db=self.db)
        pending_secrets = [pp.secret for pp in proofs_pending]
        pending_states = [
            True if p.secret in pending_secrets else False for p in proofs
        ]
        return pending_states

    async def check_proof_state(
        self, proofs: List[Proof]
    ) -> Tuple[List[bool], List[bool]]:
        """Checks if provided proofs are spend or are pending.
        Used by wallets to check if their proofs have been redeemed by a receiver or they are still in-flight in a transaction.

        Returns two lists that are in the same order as the provided proofs. Wallet must match the list
        to the proofs they have provided in order to figure out which proof is spendable or pending
        and which isn't.

        Args:
            proofs (List[Proof]): List of proofs to check.

        Returns:
            List[bool]: List of which proof is still spendable (True if still spendable, else False)
            List[bool]: List of which proof are pending (True if pending, else False)
        """
        spendable = [self._check_spendable(p) for p in proofs]
        pending = await self._check_pending(proofs)
        return spendable, pending

    async def _set_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ) -> None:
        """If none of the proofs is in the pending table (_validate_proofs_pending), adds proofs to
        the list of pending proofs or removes them. Used as a mutex for proofs.

        Args:
            proofs (List[Proof]): Proofs to add to pending table.

        Raises:
            Exception: At least one proof already in pending table.
        """
        # first we check whether these proofs are pending already
        async with self.proofs_pending_lock:
            await self._validate_proofs_pending(proofs, conn)
            for p in proofs:
                try:
                    await self.crud.set_proof_pending(proof=p, db=self.db, conn=conn)
                except Exception:
                    raise TransactionError("proofs already pending.")

    async def _unset_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ) -> None:
        """Deletes proofs from pending table.

        Args:
            proofs (List[Proof]): Proofs to delete.
        """
        async with self.proofs_pending_lock:
            for p in proofs:
                await self.crud.unset_proof_pending(proof=p, db=self.db, conn=conn)

    async def _validate_proofs_pending(
        self, proofs: List[Proof], conn: Optional[Connection] = None
    ) -> None:
        """Checks if any of the provided proofs is in the pending proofs table.

        Args:
            proofs (List[Proof]): Proofs to check.

        Raises:
            Exception: At least one of the proofs is in the pending table.
        """
        proofs_pending = await self.crud.get_proofs_pending(db=self.db, conn=conn)
        for p in proofs:
            for pp in proofs_pending:
                if p.secret == pp.secret:
                    raise TransactionError("proofs are pending.")
