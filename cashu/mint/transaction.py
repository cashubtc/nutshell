"""NUT-XX transactions: proofs and paid quotes in; blinded messages and one melt
out, with a rotation quote beside the melt. A transaction with a melt is recorded
by its melt quote."""

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

import bolt11
from loguru import logger

from ..core.base import (
    Amount,
    BlindedMessage,
    BlindedSignature,
    MeltQuote,
    Method,
    MintQuote,
    MintQuoteState,
    ProofSpentState,
    Unit,
)
from ..core.crypto.secp import PublicKey
from ..core.crypto.transcript import (
    TranscriptMintQuoteOutput,
    TranscriptQuote,
    rotation_quote_id,
)
from ..core.db import Connection, LockOptions
from ..core.errors import (
    KeysetInactiveError,
    NotAllowedError,
    QuoteAlreadyIssuedError,
    QuoteExpiredError,
    QuoteNotPaidError,
    QuotePendingError,
    QuoteSignatureInvalidError,
    TransactionError,
)
from ..core.models import (
    PostMeltQuoteResponse,
    PostMintQuoteResponse,
    PostTransactionRequest,
    PostTransactionResponse,
)
from ..core.nuts import nut20
from ..core.settings import settings
from .db.read import _spent_proof_state

if TYPE_CHECKING:
    from .ledger import Ledger

PENDING, PAID, FAILED = "PENDING", "PAID", "FAILED"
TXOUT_METHOD = "txout"


async def run(
    ledger: "Ledger", payload: PostTransactionRequest
) -> PostTransactionResponse:
    """Validate and run one transaction (NUT-XX)."""
    proofs, outputs = payload.proof_inputs, payload.blinded_outputs
    quote_outputs = payload.mint_quote_outputs
    if not (proofs or payload.mint_quote_inputs):
        raise TransactionError("transaction requires at least one input.")
    if not (outputs or payload.melt_quote_outputs):
        raise TransactionError("transaction requires at least one output.")
    # The only mint quote output is the rotation quote, backing a melt's outputs (NUT-XX).
    if len(quote_outputs) > 1:
        raise TransactionError("at most one mint quote output, the rotation quote.")
    if quote_outputs and not (outputs and payload.melt_quote_outputs):
        raise TransactionError("a rotation quote needs a melt and blinded outputs.")
    if len({q.quote for q in payload.mint_quote_inputs}) != len(
        payload.mint_quote_inputs
    ):
        raise TransactionError("transaction repeats a mint quote.")
    # A blank output takes a melt's change (NUT-08), so it needs a melt.
    if any(o.amount == 0 for o in outputs) and not payload.melt_quote_outputs:
        raise TransactionError("blank outputs are allowed only beside a melt.")
    if ledger._at_least_one_proof_has_sig_all(proofs):
        raise TransactionError("SIG_ALL inputs are not supported here.")
    for c in quote_outputs:
        key = bytes.fromhex(c.pubkey)
        PublicKey(key)  # raises unless a valid compressed point
        c.pubkey = key.hex()

    if any(m.fee_index is not None for m in payload.melt_quote_outputs):
        raise TransactionError("fee_index applies only to quotes offering fee_options.")
    melt = (
        await ledger.get_melt_quote(payload.melt_quote_outputs[0].quote)
        if payload.melt_quote_outputs
        else None
    )
    # bolt11 quotes offer no fee_options, so the reserve is the quote's own (NUT-XX).
    if melt and payload.melt_quote_outputs[0].fee_reserve != melt.fee_reserve:
        raise TransactionError("melt fee_reserve does not match the quote.")
    # The transcript commits each quote input's lock key, so the quotes come first.
    mint_quotes = [
        await ledger.get_mint_quote(q.quote) for q in payload.mint_quote_inputs
    ]
    lock_keys = [mq.pubkey or "" for mq in mint_quotes]
    if not all(lock_keys):
        raise TransactionError("quote inputs must be locked.")
    # The digest is mint-side state; the witness check below derives it.
    for p in proofs:
        p.digest = None
    verified = ledger._verify_nutroot_transaction_witnesses(
        proofs,
        outputs,
        melt,
        mint_quote_inputs=[
            TranscriptQuote(
                amount=q.amount,
                quote_id=q.quote,
                pubkey=bytes.fromhex(k),
                issued=mq.amount_issued or 0,
            )
            for q, k, mq in zip(payload.mint_quote_inputs, lock_keys, mint_quotes)
        ],
        mint_quote_outputs=[
            TranscriptMintQuoteOutput(
                pubkey=bytes.fromhex(c.pubkey), quote_id=rotation_quote_id(melt.quote)
            )
            for c in quote_outputs
            if melt
        ],
    )
    if verified is None:
        raise TransactionError("transaction has no v3 transcript.")
    digest_bytes, quote_contexts = verified
    digest = digest_bytes.hex()
    for q, k in zip(payload.mint_quote_inputs, lock_keys):
        if not nut20.verify_quote_input_witness(
            quote_contexts[q.quote].digest, k, q.witness
        ):
            raise QuoteSignatureInvalidError()

    melt_id = melt.quote if melt else None
    if proofs:
        proof_digests = [p.digest for p in proofs]
        await ledger._verify_inputs(proofs)  # clears p.digest
        for p, d in zip(proofs, proof_digests):
            p.digest = d
        ledger._verify_input_output_spending_conditions(proofs, outputs)
    if outputs:
        fixed = [o for o in outputs if o.amount]
        if fixed:
            await ledger._verify_outputs(fixed)
        if len(fixed) < len(outputs):  # blank outputs have no amount to check yet
            await ledger._verify_outputs(outputs, skip_amount_check=True)

    units = (
        {ledger.keysets[p.id].unit.name for p in proofs}
        | {q.unit for q in mint_quotes}
        | ({ledger.keysets[outputs[0].id].unit.name} if outputs else set())
        | ({melt.unit} if melt else set())
    )
    if len(units) != 1:
        raise TransactionError("transaction mixes units.")
    unit = units.pop()

    now = int(time.time())
    for q, mq in zip(payload.mint_quote_inputs, mint_quotes):
        if mq.pending:
            raise QuotePendingError()
        if mq.issued:
            raise QuoteAlreadyIssuedError()
        if not mq.paid:
            raise QuoteNotPaidError()
        if q.amount > mq.mintable:
            raise TransactionError("quote input exceeds the quote's mintable amount.")
        # A txout quote redeems once and in full (NUT-XX).
        if mq.method == TXOUT_METHOD and q.amount != mq.mintable:
            raise TransactionError("a txout quote is drawn only in full.")
        if mq.expiry and mq.expiry < now:
            raise QuoteExpiredError("quote expired")
        if mq.method == Method.bolt11.name:
            ledger._verify_mint_quote_invoice_amount(
                bolt11.decode(mq.request), Amount(Unit[mq.unit], mq.amount)
            )

    if melt:
        if ledger.disable_melt and settings.mint_disable_melt_on_error:
            raise NotAllowedError("Melt is disabled. Please contact the operator.")
        if not melt.unpaid:
            raise TransactionError(f"melt quote is not unpaid: {melt.state}")
        ledger._verify_and_get_unit_method(melt.unit, melt.method)

    # A quote input prices as its minimal split, inside NUT-02's single rounding.
    ppk = sum(ledger.keysets[p.id].input_fee_ppk for p in proofs) + sum(
        q.amount.bit_count() * settings.quote_input_fee_ppk
        for q in payload.mint_quote_inputs
    )
    fee = (ppk + 999) // 1000
    inputs = sum(p.amount for p in proofs) + sum(
        q.amount for q in payload.mint_quote_inputs
    )
    sum_outputs = sum(o.amount for o in outputs)
    melt_amount = melt.amount if melt else 0
    required = sum_outputs + melt_amount + (melt.fee_reserve if melt else 0) + fee
    if inputs != required:
        raise TransactionError(
            f"inputs ({inputs}) do not balance outputs, melt and fee ({required})."
        )
    rotation = (
        [[rotation_quote_id(melt.quote), c.pubkey] for c in quote_outputs]
        if melt
        else []
    )

    record: Dict[str, Any] = {
        "melt_quote": melt_id,
        "unit": unit,
        "mint_quotes": json.dumps(
            [[q.quote, q.amount] for q in payload.mint_quote_inputs]
        ),
        "mint_quote_outputs": json.dumps(rotation),
        "excess": inputs - fee - sum_outputs - melt_amount,
    }
    signatures: List[BlindedSignature] = []
    touched: List[MintQuote] = []
    # Acquire melt locks before mint/proof locks, including every invoice alias.
    locks = (
        [
            LockOptions(
                table="melt_quotes",
                select_statement="checking_id = :checking_id OR request = :request",
                parameters={"checking_id": melt.checking_id, "request": melt.request},
            )
        ]
        if melt
        else []
    )
    # Input reservations and outputs commit or roll back together.
    async with ledger.db.get_connection(locks=locks) as conn:
        quote_ids = [q.quote for q in payload.mint_quote_inputs]
        locked = await ledger.db_write._set_mint_quotes_pending(quote_ids, conn=conn)
        for q, mq, signed in zip(payload.mint_quote_inputs, locked, mint_quotes):
            if q.amount > mq.mintable:
                raise TransactionError(
                    "quote input exceeds the quote's mintable amount."
                )
            # The witnesses bind the state read above; a draw settled since then voids them.
            if (mq.amount_issued or 0) != (signed.amount_issued or 0):
                raise QuoteSignatureInvalidError()
        if melt:
            melt = await ledger.db_write.verify_and_set_melt_quote_pending(
                quote=melt,
                proofs=proofs,
                keysets=ledger.keysets,
                conn=conn,
                emit_events=False,
            )
            if melt.paid_time:  # paid_time marks this attempt's internal payment
                melt.paid_time = None
                await ledger.crud.update_melt_quote(quote=melt, db=ledger.db, conn=conn)
        elif proofs:
            await ledger.db_write._verify_spent_proofs_and_set_pending(
                proofs, keysets=ledger.keysets, conn=conn, emit_events=False
            )
        # Tagged with the melt quote, so its NUT-08 `change` carries the signatures.
        await ledger._store_blinded_messages(outputs, melt_id=melt_id, conn=conn)
        if melt:
            await conn.execute(
                f"""
                INSERT INTO {ledger.db.table_with_schema("melt_transactions")}
                (melt_quote, unit, mint_quotes, mint_quote_outputs, excess)
                VALUES (:melt_quote, :unit, :mint_quotes, :mint_quote_outputs, :excess)
                """,
                record,
            )
        else:
            await _finalize_proofs(ledger, proofs, conn)
            signatures, touched = await settle(ledger, record, outputs, 0, conn)
    # Events wait for the commit, so a rolled-back acceptance emits none.
    if melt:
        await ledger.events.submit(melt)
        for quote in locked:
            await ledger.events.submit(quote)
    for p in proofs:
        await ledger.events.submit(
            _spent_proof_state(p.Y, p, ProofSpentState.pending)
            if melt
            else _spent_proof_state(p.Y, p)
        )
    for quote in touched:
        await ledger.events.submit(quote)
    if melt:
        pending_melt: MeltQuote = melt

        async def pay():
            try:
                await ledger._execute_melt_payment(pending_melt, proofs, None)
            except Exception as e:
                logger.debug(f"transaction {digest} melt failed: {e}")

        if payload.prefer_async:
            asyncio.create_task(pay())
        else:
            await pay()
    return await _response(ledger, melt_id, [r[0] for r in rotation], signatures)


async def _response(
    ledger: "Ledger",
    melt_id: Optional[str],
    quote_ids: List[str],
    signatures: List[BlindedSignature],
) -> PostTransactionResponse:
    """The outcome as it stands; a melt's signatures are its NUT-08 `change`."""
    state = PAID
    melts = []
    if melt_id:
        melt = await ledger.get_melt_quote(melt_id)
        state = PAID if melt.paid else PENDING if melt.pending else FAILED
        signatures = melt.change or []
        melts.append(PostMeltQuoteResponse.from_melt_quote(melt))
    if state != PAID:
        return PostTransactionResponse(
            state=state, melt_quotes=melts, mint_quotes=[None] * len(quote_ids)
        )
    # One entry per request entry, in order; null for a rotation quote not created.
    created: List[Optional[PostMintQuoteResponse]] = []
    for quote_id in quote_ids:
        quote = await ledger.crud.get_mint_quote(quote_id=quote_id, db=ledger.db)
        created.append(PostMintQuoteResponse.from_mint_quote(quote) if quote else None)
    return PostTransactionResponse(
        state=state,
        signatures=signatures,
        melt_quotes=melts,
        mint_quotes=created,
    )


async def pending_for_melt(
    ledger: "Ledger", melt_quote: str, conn: Optional[Connection] = None
) -> Optional[Any]:
    """The pending transaction paying this melt quote, if any."""
    return await (conn or ledger.db).fetchone(
        f"""
        SELECT * FROM {ledger.db.table_with_schema("melt_transactions")}
        WHERE melt_quote = :melt_quote
        """,
        {"melt_quote": melt_quote},
    )


async def paid_internally(
    ledger: "Ledger", melt: MeltQuote, conn: Optional[Connection] = None
) -> bool:
    """A transaction's melt paid by internal settlement, its transaction still to settle.

    Internal settlement sets `paid_time` and leaves the quote PENDING; acceptance clears it.
    """
    return bool(
        melt.pending
        and melt.paid_time
        and await pending_for_melt(ledger, melt.quote, conn)
    )


async def _finalize_proofs(ledger: "Ledger", proofs, conn: Connection) -> None:
    if not proofs:
        return
    keyset_fees = {
        keyset_id: ledger.get_fees_for_proofs([p for p in proofs if p.id == keyset_id])
        for keyset_id in {p.id for p in proofs}
    }
    await ledger.db_write.finalize_pending_proofs(
        proofs=proofs,
        keysets=ledger.keysets,
        keyset_fees=keyset_fees,
        conn=conn,
        emit_events=False,
    )


async def settle(
    ledger: "Ledger",
    record,
    outputs: List[BlindedMessage],
    fee_paid: int,
    conn: Connection,
) -> Tuple[List[BlindedSignature], List[MintQuote]]:
    """Sign the outputs, issue the quote inputs and create any rotation quote.

    Returns the signatures and every quote touched, for the caller to emit once committed.
    """
    signatures: List[BlindedSignature] = []
    change = record["excess"] - fee_paid
    if change < 0:
        raise TransactionError("negative change.")
    # Held by the rotation quote if the outputs cannot be signed (NUT-XX).
    unsigned = 0
    if outputs:
        keyset = ledger.keysets[outputs[0].id]
        # Blank outputs take the change as in NUT-08; what they cannot hold stays with the mint.
        blanks = [o for o in outputs if o.amount == 0]
        fills = fill_blanks(change, keyset.amounts, len(blanks))
        if keyset.active:
            for blank, amount in zip(blanks, fills):
                blank.amount = amount
            to_sign = [o for o in outputs if o.amount]
            if to_sign:
                signatures = await ledger._sign_blinded_messages(to_sign, conn)
        elif not record["melt_quote"]:
            raise KeysetInactiveError()
        else:
            # The keyset was inactivated during the payment: nothing is signed (NUT-02).
            unsigned = sum(o.amount for o in outputs) + sum(fills)
        if record["melt_quote"]:  # drop the outputs left unsigned
            await ledger.crud.delete_blinded_messages_melt_id(
                melt_id=record["melt_quote"], db=ledger.db, conn=conn
            )
    touched: List[MintQuote] = []
    for quote_id, amount in json.loads(record["mint_quotes"]):
        quote = await ledger.crud.get_mint_quote(
            quote_id=quote_id, db=ledger.db, conn=conn
        )
        if quote is None:
            raise TransactionError("stored quote input not found.")
        quote.amount_issued = (quote.amount_issued or 0) + amount
        drawn = quote.amount_issued >= (quote.amount_paid or quote.amount)
        state = MintQuoteState.issued if drawn else MintQuoteState.paid
        ledger.db_write._set_mint_quote_state(quote, state)
        await ledger.crud.update_mint_quote(quote=quote, db=ledger.db, conn=conn)
        touched.append(quote)
    now = int(time.time())
    for quote_id, pubkey in json.loads(record["mint_quote_outputs"]):
        if unsigned <= 0:  # created only for outputs the mint could not sign
            continue
        # Moved value, not a deposit: nothing here touches keyset balances.
        quote = MintQuote(
            quote=quote_id,
            method=TXOUT_METHOD,
            request="",
            checking_id=f"{TXOUT_METHOD}:{quote_id}",
            unit=record["unit"],
            amount=unsigned,
            state=MintQuoteState.paid,
            amount_paid=unsigned,
            amount_issued=0,
            pubkey=pubkey,
            created_time=now,
            paid_time=now,
            updated_at=now,
        )
        await ledger.crud.store_mint_quote(quote=quote, db=ledger.db, conn=conn)
        touched.append(quote)
    if record["melt_quote"]:
        await _delete_pending(ledger, record["melt_quote"], conn)
    return signatures, touched


def fill_blanks(change: int, amounts: List[int], blanks: int) -> List[int]:
    """Each blank in turn takes the largest keyset amount not above what is left of `change`."""
    fills: List[int] = []
    for amount in sorted(amounts, reverse=True):
        while amount > 0 and change >= amount and len(fills) < blanks:
            fills.append(amount)
            change -= amount
    return fills


async def fail(ledger: "Ledger", record, conn: Connection) -> List[MintQuote]:
    """Return the quote inputs to paid."""
    touched: List[MintQuote] = []
    for quote_id, _ in json.loads(record["mint_quotes"]):
        quote = await ledger.crud.get_mint_quote(
            quote_id=quote_id, db=ledger.db, conn=conn
        )
        if quote is None:
            raise TransactionError("stored quote input not found.")
        ledger.db_write._set_mint_quote_state(quote, MintQuoteState.paid)
        await ledger.crud.update_mint_quote(quote=quote, db=ledger.db, conn=conn)
        touched.append(quote)
    await _delete_pending(ledger, record["melt_quote"], conn)
    return touched


async def _delete_pending(ledger: "Ledger", melt_quote: str, conn: Connection) -> None:
    await conn.execute(
        f"DELETE FROM {ledger.db.table_with_schema('melt_transactions')} WHERE melt_quote = :melt_quote",
        {"melt_quote": melt_quote},
    )
