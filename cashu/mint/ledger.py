import asyncio
import copy
import math
from typing import Dict, List, Optional, Set, Tuple

import bolt11
from loguru import logger

from ..core.base import (
    DLEQ,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    MintKeyset,
    MintKeysets,
    MintQuote,
    PostMeltQuoteRequest,
    PostMeltQuoteResponse,
    PostMintQuoteRequest,
    Proof,
)
from ..core.crypto import b_dhke
from ..core.crypto.keys import derive_pubkey, random_hash
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
from ..lightning.base import Wallet
from ..mint.crud import LedgerCrudSqlite
from .conditions import LedgerSpendingConditions
from .lightning import LedgerLightning
from .verification import LedgerVerification


class Ledger(LedgerVerification, LedgerSpendingConditions, LedgerLightning):
    locks: Dict[str, asyncio.Lock] = {}  # holds multiprocessing locks
    proofs_pending_lock: asyncio.Lock = (
        asyncio.Lock()
    )  # holds locks for proofs_pending database

    def __init__(
        self,
        db: Database,
        seed: str,
        lightning: Wallet,
        derivation_path="",
        crud=LedgerCrudSqlite(),
    ):
        self.secrets_used: Set[str] = set()
        self.master_key = seed
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud
        self.lightning = lightning
        self.pubkey = derive_pubkey(self.master_key)
        self.keysets = MintKeysets([])

    # ------- KEYS -------

    async def load_keyset(self, derivation_path, autosave=True) -> MintKeyset:
        """Load the keyset for a derivation path if it already exists. If not generate new one and store in the db.

        Args:
            derivation_path (_type_): Derivation path from which the keyset is generated.
            autosave (bool, optional): Store newly-generated keyset if not already in database. Defaults to True.

        Returns:
            MintKeyset: Keyset
        """
        # load the keyset from db
        logger.trace(f"crud: loading keyset for {derivation_path}")
        tmp_keyset_local: List[MintKeyset] = await self.crud.get_keyset(
            derivation_path=derivation_path, db=self.db
        )
        logger.trace(f"crud: loaded {len(tmp_keyset_local)} keysets")
        if tmp_keyset_local:
            # we have a keyset for this derivation path
            keyset = tmp_keyset_local[0]
            # we need to initialize it
            keyset.generate_keys()

        else:
            # no keyset for this derivation path yet
            # we generate a new keyset
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

        # store the new keyset in the current keysets
        self.keysets.keysets[keyset.id] = keyset

        # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
        if keyset.version_tuple < (0, 15):
            self.keysets.keysets[keyset.id_deprecated] = copy.copy(keyset)
            self.keysets.keysets[keyset.id_deprecated].id = keyset.id_deprecated
        # END BACKWARDS COMPATIBILITY < 0.15.0

        logger.debug(f"Loaded keyset {keyset.id}")
        return keyset

    async def init_keysets(self, autosave=True) -> None:
        """Initializes all keysets of the mint from the db. Loads all past keysets and generate their keys. Then load the current keyset.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
            not in the database yet. Will be passed to `self.load_keyset` where it is
            generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)
        logger.debug(
            f"Loaded {len(tmp_keysets)} keysets from database. Generating keys..."
        )
        # add keysets from db to current keysets
        for k in tmp_keysets:
            if k.id and k.id not in self.keysets.keysets:
                self.keysets.keysets[k.id] = k

        # generate keys for all keysets in the database
        for _, v in self.keysets.keysets.items():
            # we already generated the keys for this keyset
            if v.id and v.public_keys and len(v.public_keys):
                continue
            logger.trace(f"Generating keys for keyset {v.id}")
            v.generate_keys()

        # BEGIN BACKWARDS COMPATIBILITY < 0.15.0
        # we duplicate all old keysets also by their deprecated id
        keyset_ids = [
            v for k, v in self.keysets.keysets.items() if v.version_tuple < (0, 15)
        ]
        for v in keyset_ids:
            logger.trace(f"Loading deprecated keyset {v.id_deprecated} (new: {v.id})")
            self.keysets.keysets[v.id_deprecated] = v
        # END BACKWARDS COMPATIBILITY < 0.15.0

        logger.info(
            f"Initialized {len(self.keysets.keysets)} keysets from the database."
        )
        # load the current keyset
        self.keyset = await self.load_keyset(self.derivation_path, autosave)
        logger.info(f"Current keyset: {self.keyset.id}")

    def get_keyset(self, keyset_id: Optional[str] = None) -> Dict[int, str]:
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets.keysets:
            raise KeysetNotFoundError()
        keyset = self.keysets.keysets[keyset_id] if keyset_id else self.keyset
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
        assert quote_request.unit == "sat", "only sat supported"

        logger.trace("called request_mint")
        if settings.mint_max_peg_in and quote_request.amount > settings.mint_max_peg_in:
            raise NotAllowedError(
                f"Maximum mint amount is {settings.mint_max_peg_in} sat."
            )
        if settings.mint_peg_out_only:
            raise NotAllowedError("Mint does not allow minting new tokens.")

        logger.trace(f"requesting invoice for {quote_request.amount} satoshis")
        invoice_response = await self._request_lightning_invoice(quote_request.amount)
        logger.trace(
            f"got invoice {invoice_response.payment_request} with check id"
            f" {invoice_response.checking_id}"
        )
        assert (
            invoice_response.payment_request and invoice_response.checking_id
        ), LightningError("could not fetch invoice from Lightning backend")
        quote = MintQuote(
            quote=random_hash(),
            method="bolt11",
            request=invoice_response.payment_request,
            checking_id=invoice_response.checking_id,
            unit="sat",
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

            # Lightning
            assert quote.unit == "sat", "only sat supported"
            assert quote.method == "bolt11", "only bolt11 supported"

            if not quote.paid:
                logger.debug(f"Lightning: checking invoice {quote.checking_id}")
                status = await self.lightning.get_invoice_status(quote.checking_id)
                assert status.paid, "invoice not paid"
                await self.crud.update_mint_quote_paid(
                    quote_id=quote_id, paid=True, db=self.db
                )

            # # will raise an exception if the invoice is not paid or tokens are
            # # already issued or the requested amount is too high
            # await self._check_lightning_invoice(amount=sum_amount_outputs, id=quote_id)

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
        invoice_obj = bolt11.decode(melt_quote.request)
        assert invoice_obj.amount_msat, "invoice has no amount."
        assert melt_quote.unit == "sat", "only sat supported"
        # Lightning
        fee_reserve_sat = await self._get_lightning_fees(melt_quote.request)

        # NOTE: We do not store the fee reserve in the database.
        quote = MeltQuote(
            quote=random_hash(),
            method="bolt11",
            request=melt_quote.request,
            checking_id=invoice_obj.payment_hash,
            unit=melt_quote.unit,
            amount=int(invoice_obj.amount_msat / 1000),
            paid=False,
            fee_reserve=fee_reserve_sat,
        )
        await self.crud.store_melt_quote(quote=quote, db=self.db)
        return PostMeltQuoteResponse(
            quote=quote.quote,
            amount=quote.amount,
            fee_reserve=fee_reserve_sat,
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
        assert melt_quote.unit == "sat", "only sat supported"
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
            invoice_obj = bolt11.decode(bolt11_request)
            assert invoice_obj.amount_msat, "invoice has no amount."
            invoice_amount = math.ceil(invoice_obj.amount_msat / 1000)

            # first we check if there is a mint quote with the same payment request
            # so that we can handle the transaction internally without lightning
            fees_paid, payment_proof = 0, ""
            mint_quote = await self.crud.get_mint_quote_by_checking_id(
                checking_id=melt_quote.checking_id, db=self.db
            )
            if mint_quote:
                # we settle the transaction internally
                assert mint_quote.amount == invoice_amount, "amounts do not match"
                assert mint_quote.unit == melt_quote.unit, "units do not match"
                assert mint_quote.method == melt_quote.method, "methods do not match"
                assert not mint_quote.paid, "mint quote already paid"
                assert not mint_quote.issued, "mint quote already issued"
                # we can handle this transaction internally
                await self.crud.update_mint_quote_paid(
                    quote_id=mint_quote.quote, paid=True, db=self.db
                )

            else:
                # we need to pay the lightning invoice
                logger.debug(f"Lightning: get fees for {bolt11_request}")
                reserve_fees_sat = await self._get_lightning_fees(bolt11_request)
                # verify overspending attempt
                assert (
                    total_provided >= invoice_amount + reserve_fees_sat
                ), TransactionError(
                    "provided proofs not enough for Lightning payment. Provided:"
                    f" {total_provided}, needed: {invoice_amount + reserve_fees_sat}"
                )

                logger.debug(f"Lightning: pay invoice {bolt11_request}")
                payment = await self._pay_lightning_invoice(
                    bolt11_request, reserve_fees_sat * 1000
                )
                logger.trace("paid lightning invoice")

                logger.debug(
                    f"Melt status: {payment.ok}: preimage: {payment.preimage},"
                    f" fee_msat: {payment.fee_msat}"
                )

                if not payment.ok:
                    raise LightningError("Lightning payment unsuccessful.")

                if payment.fee_msat:
                    fees_paid = math.ceil(payment.fee_msat / 1000)
                if payment.preimage:
                    payment_proof = payment.preimage

            # melt successful, invalidate proofs
            await self._invalidate_proofs(proofs)

            # set quote as paid
            await self.crud.update_melt_quote(quote_id=quote, paid=True, db=self.db)

            # prepare change to compensate wallet for overpaid fees
            return_promises: List[BlindedSignature] = []
            if outputs and fees_paid is not None:
                return_promises = await self._generate_change_promises(
                    input_amount=total_provided,
                    output_amount=invoice_amount,
                    output_fee_paid=fees_paid,
                    outputs=outputs,
                    keyset=keyset,
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
                    if not promise.id and len(self.keysets.keysets) == 1:
                        promise.id = self.keyset.id
                    # END backwards compatibility
                    promises.append(promise)
                    return_outputs.append(output)
                    logger.trace(f"promise found: {promise}")
        return return_outputs, promises

    # ------- BLIND SIGNATURES -------

    async def _generate_promises(
        self, B_s: List[BlindedMessage], keyset: Optional[MintKeyset] = None
    ) -> list[BlindedSignature]:
        """Generates promises that sum to the given amount.

        Args:
            B_s (List[BlindedMessage]): _description_
            keyset (Optional[MintKeyset], optional): _description_. Defaults to None.

        Returns:
            list[BlindedSignature]: _description_
        """
        return [
            await self._generate_promise(
                b.amount, PublicKey(bytes.fromhex(b.B_), raw=True), keyset
            )
            for b in B_s
        ]

    async def _generate_promise(
        self, amount: int, B_: PublicKey, keyset: Optional[MintKeyset] = None
    ) -> BlindedSignature:
        """Generates a promise (Blind signature) for given amount and returns a pair (amount, C').

        Args:
            amount (int): Amount of the promise.
            B_ (PublicKey): Blinded secret (point on curve)
            keyset (Optional[MintKeyset], optional): Which keyset to use. Private keys will be taken from this keyset. Defaults to None.

        Returns:
            BlindedSignature: Generated promise.
        """
        keyset = keyset if keyset else self.keyset
        logger.trace(f"Generating promise with keyset {keyset.id}.")
        private_key_amount = keyset.private_keys[amount]
        C_, e, s = b_dhke.step2_bob(B_, private_key_amount)
        logger.trace(f"crud: _generate_promise storing promise for {amount}")
        await self.crud.store_promise(
            amount=amount,
            B_=B_.serialize().hex(),
            C_=C_.serialize().hex(),
            e=e.serialize(),
            s=s.serialize(),
            db=self.db,
            id=keyset.id,
        )
        logger.trace(f"crud: _generate_promise stored promise for {amount}")
        return BlindedSignature(
            id=keyset.id,
            amount=amount,
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
