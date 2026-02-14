import json
import pytest
import pytest_asyncio
import time
from typing import List, Tuple

from cashu.core.base import (
    MeltQuote, 
    MeltQuoteState, 
    MeltSagaState,
    Proof, 
    ProofSpentState,
    Saga,
    BlindedMessage
)
from cashu.core.errors import LightningPaymentFailedError
from cashu.core.models import PostMeltQuoteRequest
from cashu.core.settings import settings
from cashu.lightning.base import PaymentResult, PaymentResponse
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import is_fake, is_regtest, pay_if_regtest

@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=SERVER_ENDPOINT,
        db="test_data/wallet_mint_melt_saga",
        name="wallet_mint_melt_saga",
    )
    await wallet1.load_mint()
    yield wallet1

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_saga_persistence(ledger: Ledger, wallet: Wallet):
    """
    Test that saga state is persisted after setup_melt.
    """
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..." # Fake invoice
    melt_quote = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    quote = await ledger.get_melt_quote(melt_quote.quote)
    
    from cashu.mint.melt_saga import MeltSaga
    saga = MeltSaga(ledger)
    
    # 1. Setup Melt
    await saga.setup_melt(wallet.proofs, quote)
    
    # 2. Verify Saga Persistence
    db_saga = await ledger.crud.get_saga_state(db=ledger.db, operation_id=saga.operation_id)
    assert db_saga is not None
    assert db_saga.state == MeltSagaState.setup_complete
    assert db_saga.operation_id == saga.operation_id
    
    # 3. Verify Proofs Pending
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.pending for s in states)
    
    # 4. Verify Quote Pending
    updated_quote = await ledger.get_melt_quote(quote.quote)
    assert updated_quote.state == MeltQuoteState.pending

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_saga_melt_success(ledger: Ledger, wallet: Wallet):
    """
    Test full saga flow success.
    """
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
    
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..."
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    
    # Run melt (which uses saga internally)
    await ledger.melt(proofs=wallet.proofs, quote=melt_quote_resp.quote)
    
    # Verify saga is deleted (we can't easily check for ID since it was internal, 
    # but we can check no incomplete sagas)
    incomplete = await ledger.crud.get_incomplete_sagas(db=ledger.db)
    assert len(incomplete) == 0
    
    # Verify proofs spent
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.spent for s in states)
    
    # Verify quote paid
    quote = await ledger.get_melt_quote(melt_quote_resp.quote)
    assert quote.state == MeltQuoteState.paid

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_saga_payment_failure_compensates(ledger: Ledger, wallet: Wallet):
    """
    Test that payment failure triggers compensation.
    """
    settings.fakewallet_payment_state = PaymentResult.FAILED.name
    
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..."
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    
    with pytest.raises(LightningPaymentFailedError):
        await ledger.melt(proofs=wallet.proofs, quote=melt_quote_resp.quote)
        
    # Verify incomplete sagas empty
    incomplete = await ledger.crud.get_incomplete_sagas(db=ledger.db)
    assert len(incomplete) == 0
    
    # Verify proofs UNSPENT
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.unspent for s in states)
    
    # Verify quote UNPAID
    quote = await ledger.get_melt_quote(melt_quote_resp.quote)
    assert quote.state == MeltQuoteState.unpaid

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_recover_setup_complete(ledger: Ledger, wallet: Wallet):
    """
    Test recovery from SetupComplete state (crash before payment).
    """
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..."
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    quote = await ledger.get_melt_quote(melt_quote_resp.quote)
    
    from cashu.mint.melt_saga import MeltSaga
    saga = MeltSaga(ledger)
    
    # 1. Setup (Simulate crash after setup)
    await saga.setup_melt(wallet.proofs, quote)
    
    # 2. Run Recovery
    await ledger.recover_incomplete_melt_sagas()
    
    # 3. Assert Compensation
    db_saga = await ledger.crud.get_saga_state(db=ledger.db, operation_id=saga.operation_id)
    assert db_saga is None # Deleted
    
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.unspent for s in states)
    
    quote = await ledger.get_melt_quote(quote.quote)
    assert quote.state == MeltQuoteState.unpaid

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_recover_payment_attempted_success(ledger: Ledger, wallet: Wallet):
    """
    Test recovery from PaymentAttempted state where payment succeeded.
    """
    settings.fakewallet_payment_state = PaymentResult.SETTLED.name
    
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..."
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    quote = await ledger.get_melt_quote(melt_quote_resp.quote)
    
    from cashu.mint.melt_saga import MeltSaga
    saga = MeltSaga(ledger)
    
    # 1. Setup
    await saga.setup_melt(wallet.proofs, quote)
    
    # 2. Manually transition to PaymentAttempted in DB (Simulate crash during payment)
    saga.state = MeltSagaState.payment_attempted
    db_saga = Saga(
        operation_id=saga.operation_id,
        state=saga.state,
        data=json.dumps({
            "quote_id": saga.quote_id,
            "proofs": [p.to_dict(include_dleq=True) for p in saga.proofs],
            "outputs": [o.model_dump() for o in saga.change_outputs],
        }),
        created_at=int(time.time())
    )
    await ledger.crud.store_saga_state(db=ledger.db, saga=db_saga)
    
    # 3. Run Recovery (Should check backend, see SETTLED, and finalize)
    await ledger.recover_incomplete_melt_sagas()
    
    # 4. Assert Finalization
    db_saga = await ledger.crud.get_saga_state(db=ledger.db, operation_id=saga.operation_id)
    assert db_saga is None # Deleted
    
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.spent for s in states)
    
    quote = await ledger.get_melt_quote(quote.quote)
    assert quote.state == MeltQuoteState.paid

@pytest.mark.asyncio
@pytest.mark.skipif(not is_fake, reason="only fakewallet")
async def test_recover_payment_attempted_failure(ledger: Ledger, wallet: Wallet):
    """
    Test recovery from PaymentAttempted state where payment failed.
    """
    settings.fakewallet_payment_state = PaymentResult.FAILED.name
    
    mint_quote = await wallet.request_mint(64)
    await ledger.get_mint_quote(mint_quote.quote)
    await wallet.mint(64, quote_id=mint_quote.quote)
    
    invoice = "lnbcrt10n1..."
    melt_quote_resp = await ledger.melt_quote(
        PostMeltQuoteRequest(unit="sat", request=invoice)
    )
    quote = await ledger.get_melt_quote(melt_quote_resp.quote)
    
    from cashu.mint.melt_saga import MeltSaga
    saga = MeltSaga(ledger)
    
    # 1. Setup
    await saga.setup_melt(wallet.proofs, quote)
    
    # 2. Manually transition to PaymentAttempted in DB
    saga.state = MeltSagaState.payment_attempted
    db_saga = Saga(
        operation_id=saga.operation_id,
        state=saga.state,
        data=json.dumps({
            "quote_id": saga.quote_id,
            "proofs": [p.to_dict(include_dleq=True) for p in saga.proofs],
            "outputs": [o.model_dump() for o in saga.change_outputs],
        }),
        created_at=int(time.time())
    )
    await ledger.crud.store_saga_state(db=ledger.db, saga=db_saga)
    
    # 3. Run Recovery (Should check backend, see FAILED, and compensate)
    await ledger.recover_incomplete_melt_sagas()
    
    # 4. Assert Compensation
    db_saga = await ledger.crud.get_saga_state(db=ledger.db, operation_id=saga.operation_id)
    assert db_saga is None # Deleted
    
    states = await ledger.db_read.get_proofs_states([p.Y for p in wallet.proofs])
    assert all(s.unspent for s in states)
    
    quote = await ledger.get_melt_quote(quote.quote)
    assert quote.state == MeltQuoteState.unpaid
