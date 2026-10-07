"""NUT-XX transactions: proofs and paid quotes in; blinded messages, one melt
and change quotes out. The record is keyed by transaction digest."""

import asyncio
import json
import time
from typing import TYPE_CHECKING, List, Optional

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
    Unit,
)
from ..core.crypto.keys import is_bls_keyset
from ..core.crypto.nutroot import change_quote_id
from ..core.crypto.secp import PublicKey
from ..core.crypto.transcript import TranscriptChangeOutput, TranscriptQuote
from ..core.db import Connection, LockOptions
from ..core.errors import (
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

if TYPE_CHECKING:
    from .ledger import Ledger

PENDING, PAID, FAILED = "PENDING", "PAID", "FAILED"
CHANGE_METHOD = "change"


async def run(
    ledger: "Ledger", payload: PostTransactionRequest
) -> PostTransactionResponse:
    """Validate, record and run one transaction (NUT-XX)."""
    proofs, outputs = payload.proof_inputs, payload.blinded_outputs
    change_outputs = payload.change_quote_outputs
    if not (proofs or payload.mint_quote_inputs):
        raise TransactionError("transaction requires at least one input.")
    if not (outputs or payload.melt_quote_outputs or change_outputs):
        raise TransactionError("transaction requires at least one output.")
    # The amount-less entry is the remainder quote; it takes the balance (NUT-XX).
    has_remainder = any(c.amount is None for c in change_outputs)
    if sum(c.amount is None for c in change_outputs) > 1:
        raise TransactionError("at most one change quote output may omit its amount.")
    if len({q.quote for q in payload.mint_quote_inputs}) != len(
        payload.mint_quote_inputs
    ):
        raise TransactionError("transaction repeats a mint quote.")
    if any(o.amount == 0 for o in outputs):
        raise TransactionError("blank outputs are not allowed: use a change quote.")
    # Outputs cannot be signed if their keyset rotates during the payment (NUT-02);
    # the remainder quote is where their value goes then.
    if outputs and payload.melt_quote_outputs and not has_remainder:
        raise TransactionError(
            "a melt with blinded outputs requires a remainder quote."
        )
    if ledger._at_least_one_proof_has_sig_all(proofs):
        raise TransactionError("SIG_ALL inputs are not supported here.")
    for c in change_outputs:
        key = bytes.fromhex(c.pubkey)
        PublicKey(key)  # raises unless a valid compressed point
        c.pubkey = key.hex()  # canonical spelling, so key comparisons are byte-wise
    if len({c.pubkey for c in change_outputs}) != len(change_outputs):
        raise TransactionError("transaction repeats a change quote lock key.")

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
            TranscriptQuote(amount=q.amount, quote_id=q.quote, pubkey=bytes.fromhex(k))
            for q, k in zip(payload.mint_quote_inputs, lock_keys)
        ],
        change_quote_outputs=[
            TranscriptChangeOutput(pubkey=bytes.fromhex(c.pubkey), amount=c.amount)
            for c in change_outputs
        ],
    )
    assert verified is not None
    digest_bytes, quote_contexts = verified
    digest = digest_bytes.hex()

    # A resend returns the record; a FAILED one is replaced (NUT-XX).
    record = await _get_row(ledger, digest)
    if record and record["state"] != FAILED:
        return await get(ledger, digest)

    if proofs:
        proof_digests = [p.digest for p in proofs]
        await ledger._verify_inputs(proofs)  # clears p.digest
        for p, d in zip(proofs, proof_digests):
            p.digest = d
        ledger._verify_input_output_spending_conditions(proofs, outputs)
    if outputs:
        await ledger._verify_outputs(outputs)

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
    for q, mq, k in zip(payload.mint_quote_inputs, mint_quotes, lock_keys):
        if mq.pending:
            raise QuotePendingError()
        if mq.issued:
            raise QuoteAlreadyIssuedError()
        if not mq.paid:
            raise QuoteNotPaidError()
        if q.amount > mq.mintable:
            raise TransactionError("quote input exceeds the quote's mintable amount.")
        if mq.expiry and mq.expiry < now:
            raise QuoteExpiredError("quote expired")
        if mq.method == Method.bolt11.name:
            ledger._verify_mint_quote_invoice_amount(
                bolt11.decode(mq.request), Amount(Unit[mq.unit], mq.amount)
            )
        if not nut20.verify_quote_input_witness(
            quote_contexts[q.quote].digest,
            k,
            q.witness,
            quote_contexts[q.quote].outputs,
        ):
            raise QuoteSignatureInvalidError()

    if melt:
        if ledger.disable_melt and settings.mint_disable_melt_on_error:
            raise NotAllowedError("Melt is disabled. Please contact the operator.")
        if not melt.unpaid:
            raise TransactionError(f"melt quote is not unpaid: {melt.state}")
        ledger._verify_and_get_unit_method(melt.unit, melt.method)

    # A quote input prices as its minimal split, inside NUT-02's single rounding.
    ppk = sum(ledger.keysets[p.id].input_fee_ppk for p in proofs) + sum(
        q.amount.bit_count() * settings.mint_quote_input_fee_ppk
        for q in payload.mint_quote_inputs
    )
    fee = (ppk + 999) // 1000
    inputs = sum(p.amount for p in proofs) + sum(
        q.amount for q in payload.mint_quote_inputs
    )
    sum_outputs = sum(o.amount for o in outputs) + sum(
        c.amount for c in change_outputs if c.amount is not None
    )
    melt_amount = melt.amount if melt else 0
    required = sum_outputs + melt_amount + (melt.fee_reserve if melt else 0) + fee
    if inputs < required or (not has_remainder and inputs != required):
        raise TransactionError(
            f"inputs ({inputs}) do not balance outputs, melt and fee ({required})."
        )

    quote_ids = [q.quote for q in payload.mint_quote_inputs]
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
    # Reservations, outputs and the recovery record commit or roll back together.
    async with ledger.db.get_connection(locks=locks) as conn:
        await _verify_change_keys_unused(ledger, change_outputs, conn)
        locked = await ledger.db_write._set_mint_quotes_pending(quote_ids, conn=conn)
        for q, mq in zip(payload.mint_quote_inputs, locked):
            if q.amount > mq.mintable:
                raise TransactionError(
                    "quote input exceeds the quote's mintable amount."
                )
        if melt:
            melt = await ledger.db_write.verify_and_set_melt_quote_pending(
                quote=melt, proofs=proofs, keysets=ledger.keysets, conn=conn
            )
        elif proofs:
            await ledger.db_write._verify_spent_proofs_and_set_pending(
                proofs, keysets=ledger.keysets, conn=conn
            )
        await conn.execute(
            f"DELETE FROM {ledger.db.table_with_schema('transactions')} WHERE digest = :digest AND state = :state",
            {"digest": digest, "state": FAILED},
        )
        await ledger._store_blinded_messages(outputs, swap_id=digest, conn=conn)
        await conn.execute(
            f"""
            INSERT INTO {ledger.db.table_with_schema("transactions")}
            (digest, state, unit, melt_quote, mint_quotes, change_outputs, excess)
            VALUES (:digest, :state, :unit, :melt_quote, :mint_quotes, :change_outputs, :excess)
            """,
            {
                "digest": digest,
                "state": PENDING,
                "unit": unit,
                "melt_quote": melt.quote if melt else None,
                "mint_quotes": json.dumps(
                    [[q.quote, q.amount] for q in payload.mint_quote_inputs]
                ),
                "change_outputs": json.dumps(
                    [[c.pubkey, c.amount] for c in change_outputs]
                ),
                "excess": inputs - fee - sum_outputs - melt_amount,
            },
        )
        if not melt:
            await _finalize_proofs(ledger, proofs, conn)
            await settle(ledger, digest, 0, conn)
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
    return await get(ledger, digest)


async def get(ledger: "Ledger", digest: str) -> PostTransactionResponse:
    """The record for `digest`; a pending melt is checked with the backend first."""
    record = await _get_row(ledger, digest)
    if not record:
        raise TransactionError("transaction not found.")
    if record["state"] == PENDING and record["melt_quote"]:
        await ledger.get_melt_quote(record["melt_quote"])  # settles or fails it
        record = await _get_row(ledger, digest)
        assert record is not None
    signatures: List[BlindedSignature] = []
    if record["state"] == PAID:
        rows = await ledger.db.fetchall(
            f"""
            SELECT * FROM {ledger.db.table_with_schema("promises")}
            WHERE swap_id = :digest AND c_ IS NOT NULL ORDER BY order_index ASC
            """,
            {"digest": digest},
        )
        for row in rows:
            promise = BlindedSignature.from_row(row)  # type: ignore
            if not is_bls_keyset(promise.id):  # v3 carries no DLEQ
                promise.dleq = ledger._generate_dleq(
                    BlindedMessage.from_row(row), promise
                )
            signatures.append(promise)
    melts = []
    if record["melt_quote"]:
        melt = await ledger.crud.get_melt_quote(
            quote_id=record["melt_quote"], db=ledger.db
        )
        assert melt is not None
        melts.append(PostMeltQuoteResponse.from_melt_quote(melt))
    # One entry per request entry, in order; null until the quote exists (NUT-XX).
    quote_ids: List[Optional[str]] = (
        json.loads(record["change_quotes"])
        if record["change_quotes"]
        else [None] * len(json.loads(record["change_outputs"]))
    )
    change: List[Optional[PostMintQuoteResponse]] = []
    for quote_id in quote_ids:
        quote = (
            await ledger.crud.get_mint_quote(quote_id=quote_id, db=ledger.db)
            if quote_id
            else None
        )
        change.append(PostMintQuoteResponse.from_mint_quote(quote) if quote else None)
    return PostTransactionResponse(
        digest=digest,
        state=record["state"],
        signatures=signatures,
        melt_quotes=melts,
        change_quotes=change,
    )


async def _get_row(ledger: "Ledger", digest: str, conn: Optional[Connection] = None):
    return await (conn or ledger.db).fetchone(
        f"SELECT * FROM {ledger.db.table_with_schema('transactions')} WHERE digest = :digest",
        {"digest": digest},
    )


async def pending_for_melt(
    ledger: "Ledger", melt_quote: str, conn: Optional[Connection] = None
) -> Optional[str]:
    """Digest of the pending transaction paying this melt quote, if any."""
    row = await (conn or ledger.db).fetchone(
        f"""
        SELECT digest FROM {ledger.db.table_with_schema("transactions")}
        WHERE melt_quote = :melt_quote AND state = :state
        """,
        {"melt_quote": melt_quote, "state": PENDING},
    )
    return row["digest"] if row else None


async def _verify_change_keys_unused(
    ledger: "Ledger", change_outputs, conn: Connection
) -> None:
    """A lock key names one change quote: refuse one already created or pending."""
    for c in change_outputs:
        quote_id = change_quote_id(bytes.fromhex(c.pubkey))
        if await ledger.crud.get_mint_quote(quote_id=quote_id, db=ledger.db, conn=conn):
            raise TransactionError("change quote lock key already used.")
        # Pending transactions hold their keys in the record, not as quotes yet.
        row = await conn.fetchone(
            f"""
            SELECT 1 FROM {ledger.db.table_with_schema("transactions")}
            WHERE state = :state AND change_outputs LIKE :key
            """,
            {"state": PENDING, "key": f'%"{c.pubkey}"%'},
        )
        if row:
            raise TransactionError("change quote lock key already used.")


async def _finalize_proofs(ledger: "Ledger", proofs, conn: Connection) -> None:
    if not proofs:
        return
    keyset_fees = {
        keyset_id: ledger.get_fees_for_proofs([p for p in proofs if p.id == keyset_id])
        for keyset_id in {p.id for p in proofs}
    }
    await ledger.db_write.finalize_pending_proofs(
        proofs=proofs, keysets=ledger.keysets, keyset_fees=keyset_fees, conn=conn
    )


async def settle(
    ledger: "Ledger", digest: str, fee_paid: int, conn: Connection
) -> None:
    """Sign the outputs, issue the quote inputs and create the change quotes."""
    record = await _get_row(ledger, digest, conn=conn)
    assert record is not None and record["state"] == PENDING
    rows = await conn.fetchall(
        f"""
        SELECT * FROM {ledger.db.table_with_schema("promises")}
        WHERE swap_id = :digest AND c_ IS NULL ORDER BY order_index ASC
        """,
        {"digest": digest},
    )
    unsigned = 0
    if rows:
        messages = [BlindedMessage.from_row(r) for r in rows]
        if ledger.keysets[messages[0].id].active:
            await ledger._sign_blinded_messages(messages, conn)
        else:
            # The keyset rotated during the payment: nothing is signed (NUT-02),
            # the outputs' value returns through the remainder quote.
            unsigned = sum(m.amount for m in messages)
            await conn.execute(
                f"""
                DELETE FROM {ledger.db.table_with_schema("promises")}
                WHERE swap_id = :digest AND c_ IS NULL
                """,
                {"digest": digest},
            )
    for quote_id, amount in json.loads(record["mint_quotes"]):
        quote = await ledger.crud.get_mint_quote(
            quote_id=quote_id, db=ledger.db, conn=conn
        )
        assert quote is not None
        quote.amount_issued = (quote.amount_issued or 0) + amount
        drawn = quote.amount_issued >= (quote.amount_paid or quote.amount)
        state = MintQuoteState.issued if drawn else MintQuoteState.paid
        ledger.db_write._set_mint_quote_state(quote, state)
        await ledger.crud.update_mint_quote(quote=quote, db=ledger.db, conn=conn)
    change = record["excess"] + unsigned - fee_paid
    if change < 0:
        raise TransactionError("negative change.")
    change_quotes: List[Optional[str]] = []
    now = int(time.time())
    for pubkey, fixed in json.loads(record["change_outputs"]):
        amount = fixed if fixed is not None else change
        if amount <= 0:  # a remainder quote with zero change is not created
            change_quotes.append(None)
            continue
        # Moved value, not a deposit: nothing here touches keyset balances.
        quote = MintQuote(
            quote=change_quote_id(bytes.fromhex(pubkey)),
            method=CHANGE_METHOD,
            request=digest,
            checking_id=f"{CHANGE_METHOD}:{digest}:{len(change_quotes)}",
            unit=record["unit"],
            amount=amount,
            state=MintQuoteState.paid,
            amount_paid=amount,
            amount_issued=0,
            pubkey=pubkey,
            created_time=now,
            paid_time=now,
            updated_at=now,
        )
        await ledger.crud.store_mint_quote(quote=quote, db=ledger.db, conn=conn)
        change_quotes.append(quote.quote)
    await conn.execute(
        f"""
        UPDATE {ledger.db.table_with_schema("transactions")}
        SET state = :state, change_quotes = :change_quotes WHERE digest = :digest
        """,
        {"state": PAID, "change_quotes": json.dumps(change_quotes), "digest": digest},
    )


async def fail(ledger: "Ledger", digest: str, conn: Connection) -> None:
    """Return the quote inputs to paid and drop the reserved outputs."""
    record = await _get_row(ledger, digest, conn=conn)
    assert record is not None
    for quote_id, _ in json.loads(record["mint_quotes"]):
        quote = await ledger.crud.get_mint_quote(
            quote_id=quote_id, db=ledger.db, conn=conn
        )
        assert quote is not None
        ledger.db_write._set_mint_quote_state(quote, MintQuoteState.paid)
        await ledger.crud.update_mint_quote(quote=quote, db=ledger.db, conn=conn)
    await conn.execute(
        f"""
        DELETE FROM {ledger.db.table_with_schema("promises")}
        WHERE swap_id = :digest AND c_ IS NULL
        """,
        {"digest": digest},
    )
    await conn.execute(
        f"UPDATE {ledger.db.table_with_schema('transactions')} SET state = :state WHERE digest = :digest",
        {"state": FAILED, "digest": digest},
    )
