import asyncio
from typing import List, Tuple

import bolt11
import pytest
import pytest_asyncio

from cashu.core.base import MeltQuote, MeltQuoteState, Proof
from cashu.core.crypto.aes import AESCipher
from cashu.core.db import Database
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import (
    SLEEP_TIME,
    cancel_invoice,
    get_hold_invoice,
    is_fake,
    is_regtest,
    pay_if_regtest,
    settle_invoice,
)

SEED = "TEST_PRIVATE_KEY"
DERIVATION_PATH = "m/0'/0'/0'"
DECRYPTON_KEY = "testdecryptionkey"
ENCRYPTED_SEED = "U2FsdGVkX1_7UU_-nVBMBWDy_9yDu4KeYb7MH8cJTYQGD4RWl82PALH8j-HKzTrI"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs: List[Proof], expected: int):
    """Assert amounts the proofs contain."""
    assert [p.amount for p in proofs] == expected


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_api_deprecated",
        name="wallet_mint_api_deprecated",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_init_keysets(ledger: Ledger):
    ledger.keysets = {}
    await ledger.init_keysets()
    assert len(ledger.keysets) == 2


@pytest.mark.asyncio
async def test_ledger_encrypt():
    aes = AESCipher(DECRYPTON_KEY)
    encrypted = aes.encrypt(SEED.encode())
    assert aes.decrypt(encrypted) == SEED


@pytest.mark.asyncio
async def test_ledger_decrypt():
    aes = AESCipher(DECRYPTON_KEY)
    assert aes.decrypt(ENCRYPTED_SEED) == SEED


@pytest.mark.asyncio
async def test_decrypt_seed():
    ledger = Ledger(
        db=Database("mint", settings.mint_database),
        seed=SEED,
        seed_decryption_key=None,
        derivation_path=DERIVATION_PATH,
        backends={},
        crud=LedgerCrudSqlite(),
    )
    await ledger.init_keysets()
    assert ledger.keyset.seed == SEED
    private_key_1 = (
        ledger.keysets[list(ledger.keysets.keys())[0]].private_keys[1].serialize()
    )
    assert (
        private_key_1
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    pubkeys = ledger.keysets[list(ledger.keysets.keys())[0]].public_keys
    assert pubkeys
    assert (
        pubkeys[1].serialize().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )

    ledger_encrypted = Ledger(
        db=Database("mint", settings.mint_database),
        seed=ENCRYPTED_SEED,
        seed_decryption_key=DECRYPTON_KEY,
        derivation_path=DERIVATION_PATH,
        backends={},
        crud=LedgerCrudSqlite(),
    )
    await ledger_encrypted.init_keysets()
    assert ledger_encrypted.keyset.seed == SEED
    private_key_1 = (
        ledger_encrypted.keysets[list(ledger_encrypted.keysets.keys())[0]]
        .private_keys[1]
        .serialize()
    )
    assert (
        private_key_1
        == "8300050453f08e6ead1296bb864e905bd46761beed22b81110fae0751d84604d"
    )
    pubkeys_encrypted = ledger_encrypted.keysets[
        list(ledger_encrypted.keysets.keys())[0]
    ].public_keys
    assert pubkeys_encrypted
    assert (
        pubkeys_encrypted[1].serialize().hex()
        == "02194603ffa36356f4a56b7df9371fc3192472351453ec7398b8da8117e7c3e104"
    )


async def create_pending_melts(
    ledger: Ledger, check_id: str = "checking_id"
) -> Tuple[Proof, MeltQuote]:
    """Helper function for startup tests for fakewallet. Creates fake pending melt
    quote and fake proofs that are in the pending table that look like they're being
    used to pay the pending melt quote."""
    quote_id = "quote_id"
    quote = MeltQuote(
        quote=quote_id,
        method="bolt11",
        request="asdasd",
        checking_id=check_id,
        unit="sat",
        state=MeltQuoteState.pending,
        amount=100,
        fee_reserve=1,
    )
    await ledger.crud.store_melt_quote(
        quote=quote,
        db=ledger.db,
    )
    pending_proof = Proof(amount=123, C="asdasd", secret="asdasd", id=quote_id)
    await ledger.crud.set_proof_pending(
        db=ledger.db,
        proof=pending_proof,
        quote_id=quote_id,
    )
    # expect a pending melt quote
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    return pending_proof, quote


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_startup_fakewallet_pending_quote_success(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote was paid."""
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
    # run startup routinge
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].spent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only fake wallet")
async def test_startup_fakewallet_pending_quote_failure(ledger: Ledger):
    """Startup routine test. Expects that a pending proofs are removed form the pending db
    after the startup routine determines that the associated melt quote failed to pay.

    The failure is simulated by setting the fakewallet_payment_state to False.
    """
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.FAILED.name
    # run startup routinge
    await ledger.startup_ledger()

    # expect that no pending tokens are in db anymore
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are unspent
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].unspent


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only for fake wallet")
async def test_startup_fakewallet_pending_quote_pending(ledger: Ledger):
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.PENDING.name
    # run startup routinge
    await ledger.startup_ledger()

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are still pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_regtest, reason="only for fake wallet")
async def test_startup_fakewallet_pending_quote_unknown(ledger: Ledger):
    # unknown state simulates a failure th check the lightning backend
    pending_proof, quote = await create_pending_melts(ledger)
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending
    settings.fakewallet_payment_state = PaymentResult.UNKNOWN.name
    # run startup routinge
    await ledger.startup_ledger()

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    assert melt_quotes[0].state == MeltQuoteState.pending

    # expect that proofs are still pending
    states = await ledger.db_read.get_proofs_states([pending_proof.Y])
    assert states[0].pending


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_startup_regtest_pending_quote_pending(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    # run startup routinge
    await ledger.startup_ledger()

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes

    # expect that proofs are still pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    # only now settle the invoice
    settle_invoice(preimage=preimage)


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_startup_regtest_pending_quote_success(wallet: Wallet, ledger: Ledger):
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)
    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    settle_invoice(preimage=preimage)
    await asyncio.sleep(SLEEP_TIME)

    # run startup routinge
    await ledger.startup_ledger()

    # expect that no melt quote is pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are spent
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.spent for s in states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_startup_regtest_pending_quote_failure(wallet: Wallet, ledger: Ledger):
    """Simulate a failure to pay the hodl invoice by canceling it."""
    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    invoice_obj = bolt11.decode(invoice_payment_request)
    preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    cancel_invoice(preimage_hash=preimage_hash)
    await asyncio.sleep(SLEEP_TIME)

    # run startup routinge
    await ledger.startup_ledger()

    # expect that no melt quote is pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert not melt_quotes

    # expect that proofs are unspent
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.unspent for s in states])


@pytest.mark.asyncio
@pytest.mark.skipif(is_fake, reason="only regtest")
async def test_startup_regtest_pending_quote_unknown(wallet: Wallet, ledger: Ledger):
    """Simulate an unknown payment by executing a pending payment, then
    manipulating the melt_quote in the mint's db so that its checking_id
    points to an unknown payment."""

    # fill wallet
    mint_quote = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet.mint(64, quote_id=mint_quote.quote)
    assert wallet.balance == 64

    # create hodl invoice
    preimage, invoice_dict = get_hold_invoice(16)
    invoice_payment_request = str(invoice_dict["payment_request"])
    invoice_obj = bolt11.decode(invoice_payment_request)
    preimage_hash = invoice_obj.payment_hash

    # wallet pays the invoice
    quote = await wallet.melt_quote(invoice_payment_request)
    total_amount = quote.amount + quote.fee_reserve
    _, send_proofs = await wallet.swap_to_send(wallet.proofs, total_amount)
    asyncio.create_task(
        wallet.melt(
            proofs=send_proofs,
            invoice=invoice_payment_request,
            fee_reserve_sat=quote.fee_reserve,
            quote_id=quote.quote,
        )
    )
    await asyncio.sleep(SLEEP_TIME)

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    # before we cancel the payment, we manipulate the melt_quote's checking_id so
    # that the mint fails to look up the payment and treats the payment as failed during startup
    melt_quote = await ledger.crud.get_melt_quote_by_request(
        db=ledger.db, request=invoice_payment_request
    )
    assert melt_quote
    assert melt_quote.pending

    # manipulate the checking_id 32 bytes hexadecmial
    melt_quote.checking_id = "a" * 64
    await ledger.crud.update_melt_quote(quote=melt_quote, db=ledger.db)

    await asyncio.sleep(SLEEP_TIME)

    # run startup routine
    await ledger.startup_ledger()

    # expect that melt quote is still pending
    melt_quotes = await ledger.crud.get_all_melt_quotes_from_pending_proofs(
        db=ledger.db
    )
    assert melt_quotes
    assert melt_quotes[0].state == MeltQuoteState.pending

    # expect that proofs are pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in send_proofs])
    assert all([s.pending for s in states])

    # clean up
    cancel_invoice(preimage_hash=preimage_hash)
