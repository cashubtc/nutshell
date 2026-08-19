import asyncio
import os
import time

import pytest
import pytest_asyncio

from cashu.core.base import MintQuoteState
from cashu.core.crypto.secp import PrivateKey
from cashu.core.errors import BatchDuplicateQuotesError, BatchSizeExceededError
from cashu.core.models import PostMintBatchRequest, PostMintQuoteCheckRequest
from cashu.core.nuts import nut20
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.wallet.wallet import Wallet
from tests.helpers import pay_if_regtest

BASE_URL = "http://localhost:3337"


@pytest_asyncio.fixture(scope="function")
async def wallet(ledger: Ledger):
    wallet1 = await Wallet.with_db(
        url=BASE_URL,
        db="test_data/wallet_mint_api_batch",
        name="wallet_mint_api_batch",
    )
    await wallet1.load_mint()
    yield wallet1


@pytest.mark.asyncio
async def test_ledger_mint_quote_check(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    quotes = await ledger.mint_quote_check(
        PostMintQuoteCheckRequest(quotes=[mint_quote1.quote, mint_quote2.quote])
    )
    assert len(quotes) == 2
    assert quotes[0].quote == mint_quote1.quote
    assert quotes[0].amount == 64
    assert quotes[0].state.value in ["UNPAID", "PAID"]
    assert quotes[1].quote == mint_quote2.quote
    assert quotes[1].amount == 32
    assert quotes[1].state.value in ["UNPAID", "PAID"]


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_returns_positional_unknown_quotes(
    ledger: Ledger, wallet: Wallet
):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    quotes = await ledger.mint_quote_check(
        PostMintQuoteCheckRequest(
            quotes=[
                mint_quote1.quote,
                "not-a-valid-quote-id",
                "01989999-9999-7999-8999-999999999999",
                mint_quote2.quote,
            ]
        )
    )

    assert quotes[0] and quotes[0].quote == mint_quote1.quote
    assert quotes[1] is None
    assert quotes[2] is None
    assert quotes[3] and quotes[3].quote == mint_quote2.quote


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_returns_none_for_unknown_quotes(
    ledger: Ledger,
):
    quotes = await ledger.mint_quote_check(
        PostMintQuoteCheckRequest(
            quotes=[
                "not-a-valid-quote-id",
                "01989999-9999-7999-8999-999999999999",
            ]
        )
    )

    assert quotes == [None, None]


@pytest.mark.asyncio
async def test_ledger_mint_batch_success(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote, mint_quote2.quote],
            quote_amounts=[64, 32],
            outputs=outputs,
            signatures=[sig1, sig2],
        )
    )

    assert len(promises) == 2
    assert promises[0].amount == 64
    assert promises[1].amount == 32

    quote1 = await ledger.get_mint_quote(mint_quote1.quote)
    quote2 = await ledger.get_mint_quote(mint_quote2.quote)
    assert quote1.issued_time is not None
    assert quote2.issued_time is not None


@pytest.mark.asyncio
async def test_ledger_mint_batch_wrong_amount(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([32, 32], secrets, rs)

    assert mint_quote1.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote],
                quote_amounts=[32],
                outputs=outputs,
                signatures=[sig1],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "does not match quote" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_duplicate_quotes(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote, mint_quote1.quote],
                quote_amounts=[64, 64],
                outputs=[],
                signatures=[None, None],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "Duplicate quote IDs provided" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_race(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    req = PostMintBatchRequest(
        quotes=[mint_quote1.quote, mint_quote2.quote],
        quote_amounts=[64, 32],
        outputs=outputs,
        signatures=[sig1, sig2],
    )

    results = await asyncio.gather(
        ledger.mint_batch(req), ledger.mint_batch(req), return_exceptions=True
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    exceptions = [r for r in results if isinstance(r, Exception)]

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
    assert len(exceptions) == 1, f"Expected 1 exception, got {len(exceptions)}"


@pytest.mark.asyncio
async def test_ledger_mint_batch_race_permutations(ledger: Ledger, wallet: Wallet):
    """Test to ensure that locking order is deterministic and prevents deadlocks when two requests provide different permutations of quotes"""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    req1 = PostMintBatchRequest(
        quotes=[mint_quote1.quote, mint_quote2.quote],
        quote_amounts=[64, 32],
        outputs=outputs,
        signatures=[sig1, sig2],
    )

    # Different permutation
    req2 = PostMintBatchRequest(
        quotes=[mint_quote2.quote, mint_quote1.quote],
        quote_amounts=[32, 64],
        outputs=outputs,
        signatures=[sig2, sig1],
    )

    results = await asyncio.gather(
        ledger.mint_batch(req1), ledger.mint_batch(req2), return_exceptions=True
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    exceptions = [r for r in results if isinstance(r, Exception)]

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
    assert len(exceptions) == 1, f"Expected 1 exception, got {len(exceptions)}"

    # Ensure the exception is not a timeout or deadlock error but a transaction error
    assert any(
        "already pending" in str(e) or "already issued" in str(e) for e in exceptions
    ), f"Unexpected exception: {exceptions}"


@pytest.mark.asyncio
async def test_ledger_mint_batch_and_normal_mint_race(ledger: Ledger, wallet: Wallet):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs_gen, derivation_paths = await wallet.generate_secrets_from_to(
        10000, 10002
    )
    outputs, _ = wallet._construct_outputs([64, 32], secrets[:2], rs_gen[:2])

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    req_batch = PostMintBatchRequest(
        quotes=[mint_quote1.quote, mint_quote2.quote],
        quote_amounts=[64, 32],
        outputs=outputs,
        signatures=[sig1, sig2],
    )

    outputs_normal, _ = wallet._construct_outputs([64], [secrets[2]], [rs_gen[2]])
    sig_normal = nut20.sign_mint_quote(
        mint_quote1.quote, outputs_normal, mint_quote1.privkey
    )

    results = await asyncio.gather(
        ledger.mint_batch(req_batch),
        ledger.mint(
            outputs=outputs_normal, quote_id=mint_quote1.quote, signature=sig_normal
        ),
        return_exceptions=True,
    )

    successes = [r for r in results if not isinstance(r, Exception)]
    exceptions = [r for r in results if isinstance(r, Exception)]

    assert len(successes) == 1, f"Expected 1 success, got {len(successes)}"
    assert len(exceptions) == 1, f"Expected 1 exception, got {len(exceptions)}"


def test_mint_batch_and_check_validation():
    from pydantic import ValidationError

    from cashu.core.constants import MAX_QUOTE_ID_LEN

    # 1. Check PostMintBatchRequest with too long quote ID
    long_quote = "a" * (MAX_QUOTE_ID_LEN + 1)
    with pytest.raises(ValidationError) as excinfo:
        PostMintBatchRequest(
            quotes=[long_quote],
            outputs=[],
        )
    assert "at most" in str(excinfo.value) or "max_length" in str(excinfo.value)

    # 2. Check PostMintBatchRequest with too many quotes
    too_many_quotes = ["a"] * (settings.mint_max_request_length + 1)
    with pytest.raises(ValidationError) as excinfo:
        PostMintBatchRequest(
            quotes=too_many_quotes,
            outputs=[],
        )
    assert "at most" in str(excinfo.value) or "max_length" in str(excinfo.value)

    # 3. Check PostMintQuoteCheckRequest with too long quote ID
    # (overlong IDs are rejected with a validation error as DoS protection)
    with pytest.raises(ValidationError) as excinfo:
        PostMintQuoteCheckRequest(
            quotes=[long_quote],
        )
    assert "at most" in str(excinfo.value) or "max_length" in str(excinfo.value)

    # 4. PostMintQuoteCheckRequest accepts any number of quotes: oversized
    # batches are rejected by the mint with error 11017 (see
    # test_ledger_mint_quote_check_rejects_oversized_batch)
    check_req = PostMintQuoteCheckRequest(quotes=too_many_quotes)
    assert len(check_req.quotes) == settings.mint_max_request_length + 1


@pytest.mark.asyncio
async def test_ledger_mint_batch_post_sign_failure_leaves_pending(
    ledger: Ledger, wallet: Wallet, monkeypatch
):
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    async def mock_issue_mint_quotes(quote_ids, amounts):
        raise Exception("failed to acquire database lock on mint_quotes")

    monkeypatch.setattr(
        ledger.db_write,
        "_issue_mint_quotes",
        mock_issue_mint_quotes,
    )

    req = PostMintBatchRequest(
        quotes=[mint_quote1.quote, mint_quote2.quote],
        quote_amounts=[64, 32],
        outputs=outputs,
        signatures=[sig1, sig2],
    )

    # Calling mint_batch should raise our simulated exception
    with pytest.raises(Exception) as exc:
        await ledger.mint_batch(req)
    assert "failed to acquire database lock on mint_quotes" in str(exc.value)

    # Verify that the quotes are left in PENDING state (not reverted to PAID)
    q1 = await ledger.get_mint_quote(mint_quote1.quote)
    q2 = await ledger.get_mint_quote(mint_quote2.quote)
    assert q1 is not None
    assert q2 is not None
    assert q1.state == MintQuoteState.pending
    assert q2.state == MintQuoteState.pending

    # Re-minting with the same quotes should fail because they are PENDING (which prevents double-issuance)
    monkeypatch.undo()  # restore original unset_mint_quotes_pending so we can attempt a normal mint, but it should fail on pending check

    secrets2, rs2, derivation_paths2 = await wallet.generate_secrets_from_to(
        10002, 10003
    )
    outputs2, rs2 = wallet._construct_outputs([64, 32], secrets2, rs2)
    sig1_2 = nut20.sign_mint_quote(mint_quote1.quote, outputs2, mint_quote1.privkey)
    sig2_2 = nut20.sign_mint_quote(mint_quote2.quote, outputs2, mint_quote2.privkey)

    req2 = PostMintBatchRequest(
        quotes=[mint_quote1.quote, mint_quote2.quote],
        quote_amounts=[64, 32],
        outputs=outputs2,
        signatures=[sig1_2, sig2_2],
    )

    with pytest.raises(Exception) as exc:
        await ledger.mint_batch(req2)
    assert "mint quote already pending" in str(exc.value)


@pytest.mark.asyncio
async def test_ledger_mint_batch_missing_signature_for_locked_quote(
    ledger: Ledger, wallet: Wallet
):
    """Locked quote without signature should fail."""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote, mint_quote2.quote],
                quote_amounts=[64, 32],
                outputs=outputs,
                signatures=[sig1, None],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "Signature" in str(e) or "signature" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_invalid_signature(ledger: Ledger, wallet: Wallet):
    """Wrong signature for locked quote should fail."""
    import os

    from cashu.core.crypto.secp import PrivateKey

    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([64], secrets, rs)

    assert mint_quote1.privkey

    wrong_privkey = PrivateKey(os.urandom(32))
    wrong_sig = nut20.sign_mint_quote(
        mint_quote1.quote, outputs, wrong_privkey.secret.hex()
    )

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote],
                quote_amounts=[64],
                outputs=outputs,
                signatures=[wrong_sig],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "Signature" in str(e) or "signature" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_mixed_locked_unlocked(ledger: Ledger, wallet: Wallet):
    """Batch with one locked and one unlocked quote should succeed."""
    await wallet.load_mint()
    # locked quote (NUT-20 pubkey set)
    mint_quote1 = await wallet.request_mint(64)
    # unlocked quote (no pubkey -> no signature required)
    mint_quote2 = await wallet.mint_quote(32, wallet.unit)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote, mint_quote2.quote],
            quote_amounts=[64, 32],
            outputs=outputs,
            signatures=[sig1, None],
        )
    )

    assert len(promises) == 2
    assert promises[0].amount == 64
    assert promises[1].amount == 32


@pytest.mark.asyncio
async def test_ledger_mint_batch_already_issued(ledger: Ledger, wallet: Wallet):
    """Attempting to mint already-issued quotes should fail."""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote, mint_quote2.quote],
            quote_amounts=[64, 32],
            outputs=outputs,
            signatures=[sig1, sig2],
        )
    )

    secrets2, rs2, derivation_paths2 = await wallet.generate_secrets_from_to(
        10002, 10003
    )
    outputs2, rs2 = wallet._construct_outputs([64, 32], secrets2, rs2)

    sig1_2 = nut20.sign_mint_quote(mint_quote1.quote, outputs2, mint_quote1.privkey)
    sig2_2 = nut20.sign_mint_quote(mint_quote2.quote, outputs2, mint_quote2.privkey)

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote, mint_quote2.quote],
                quote_amounts=[64, 32],
                outputs=outputs2,
                signatures=[sig1_2, sig2_2],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "already issued" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_empty_quotes(ledger: Ledger, wallet: Wallet):
    """Empty quotes array should fail."""
    await wallet.load_mint()

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[],
                quote_amounts=[],
                outputs=[],
                signatures=[],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "empty" in str(e).lower() or "must not be empty" in str(e)


@pytest.mark.asyncio
async def test_ledger_mint_batch_single_quote(ledger: Ledger, wallet: Wallet):
    """Single quote batch should succeed."""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote1.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([64], secrets, rs)

    assert mint_quote1.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote],
            quote_amounts=[64],
            outputs=outputs,
            signatures=[sig1],
        )
    )

    assert len(promises) == 1
    assert promises[0].amount == 64


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_nonexistent_quote(
    ledger: Ledger, wallet: Wallet
):
    """Checking nonexistent quotes should return positional unknowns."""
    await wallet.load_mint()

    quotes = await ledger.mint_quote_check(
        PostMintQuoteCheckRequest(quotes=["nonexistent_quote_id"])
    )

    assert quotes == [None]


@pytest.mark.asyncio
async def test_ledger_mint_batch_atomicity_one_invalid(ledger: Ledger, wallet: Wallet):
    """If one quote in batch is invalid, none should be minted."""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    # quote2 is locked but receives an invalid signature, so the whole batch must fail
    wrong_privkey = PrivateKey(os.urandom(32))
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, wrong_privkey.secret.hex())

    try:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote1.quote, mint_quote2.quote],
                quote_amounts=[64, 32],
                outputs=outputs,
                signatures=[sig1, sig2],
            )
        )
        assert False, "Expected Exception"
    except Exception as e:
        assert "Signature" in str(e) or "signature" in str(e)

    q1_after = await ledger.crud.get_mint_quote(
        quote_id=mint_quote1.quote, db=ledger.db
    )
    assert (
        q1_after.state.value == "PAID"
    ), f"Quote1 should still be PAID, got {q1_after.state.value}"

    secrets2, rs2, derivation_paths2 = await wallet.generate_secrets_from_to(
        10002, 10002
    )
    outputs2, rs2 = wallet._construct_outputs([64], secrets2, rs2)
    sig1_2 = nut20.sign_mint_quote(mint_quote1.quote, outputs2, mint_quote1.privkey)

    promises = await ledger.mint(
        outputs=outputs2,
        quote_id=mint_quote1.quote,
        signature=sig1_2,
    )
    assert len(promises) == 1
    assert promises[0].amount == 64


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_rejects_duplicate_quotes(
    ledger: Ledger, wallet: Wallet
):
    """Duplicate quote IDs must be rejected with error 11016."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    with pytest.raises(BatchDuplicateQuotesError):
        await ledger.mint_quote_check(
            PostMintQuoteCheckRequest(quotes=[mint_quote.quote, mint_quote.quote])
        )


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_rejects_oversized_batch(ledger: Ledger):
    """Batches larger than max_batch_size must be rejected with error 11017."""
    too_many_quotes = ["quote"] * (settings.mint_max_request_length + 1)

    with pytest.raises(BatchSizeExceededError):
        await ledger.mint_quote_check(PostMintQuoteCheckRequest(quotes=too_many_quotes))


@pytest.mark.asyncio
async def test_ledger_mint_quote_check_empty_quotes(ledger: Ledger):
    """An empty quotes array is valid and returns an empty list."""
    quotes = await ledger.mint_quote_check(PostMintQuoteCheckRequest(quotes=[]))
    assert quotes == []


@pytest.mark.asyncio
async def test_ledger_mint_batch_without_quote_amounts(ledger: Ledger, wallet: Wallet):
    """Omitted quote_amounts mint each quote's full currently mintable amount."""
    await wallet.load_mint()
    mint_quote1 = await wallet.request_mint(64)
    mint_quote2 = await wallet.request_mint(32)

    await pay_if_regtest(mint_quote1.request)
    await pay_if_regtest(mint_quote2.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 32], secrets, rs)

    assert mint_quote1.privkey
    assert mint_quote2.privkey

    sig1 = nut20.sign_mint_quote(mint_quote1.quote, outputs, mint_quote1.privkey)
    sig2 = nut20.sign_mint_quote(mint_quote2.quote, outputs, mint_quote2.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote1.quote, mint_quote2.quote],
            outputs=outputs,
            signatures=[sig1, sig2],
        )
    )

    assert len(promises) == 2

    quote1 = await ledger.crud.get_mint_quote(quote_id=mint_quote1.quote, db=ledger.db)
    quote2 = await ledger.crud.get_mint_quote(quote_id=mint_quote2.quote, db=ledger.db)
    assert quote1 and quote1.amount_issued == 64
    assert quote1.state == MintQuoteState.issued
    assert quote2 and quote2.amount_issued == 32
    assert quote2.state == MintQuoteState.issued


@pytest.mark.asyncio
async def test_ledger_mint_batch_expired_quote(ledger: Ledger, wallet: Wallet):
    """A quote with a positive mintable amount remains mintable after expiry."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote.request)

    # expire the quote
    quote = await ledger.get_mint_quote(mint_quote.quote)
    assert quote.paid
    quote.expiry = int(time.time()) - 100
    await ledger.crud.update_mint_quote(quote=quote, db=ledger.db)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([64], secrets, rs)

    assert mint_quote.privkey
    sig = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote.quote],
            quote_amounts=[64],
            outputs=outputs,
            signatures=[sig],
        )
    )

    assert len(promises) == 1
    assert promises[0].amount == 64


@pytest.mark.asyncio
async def test_ledger_mint_batch_amount_exceeds_mintable(
    ledger: Ledger, wallet: Wallet
):
    """Allocating more than a quote's mintable amount must fail atomically."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10001)
    outputs, rs = wallet._construct_outputs([64, 64], secrets, rs)

    assert mint_quote.privkey
    sig = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)

    with pytest.raises(Exception) as exc:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote.quote],
                quote_amounts=[128],
                outputs=outputs,
                signatures=[sig],
            )
        )
    assert "exceeds mintable amount" in str(exc.value)

    # nothing was issued
    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote and quote.amount_issued == 0
    assert quote.state == MintQuoteState.paid


@pytest.mark.asyncio
async def test_ledger_mint_batch_non_positive_amount(ledger: Ledger, wallet: Wallet):
    """Non-positive quote amounts must be rejected."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote.request)

    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([64], secrets, rs)

    assert mint_quote.privkey
    sig = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)

    with pytest.raises(Exception) as exc:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote.quote],
                quote_amounts=[0],
                outputs=outputs,
                signatures=[sig],
            )
        )
    assert "must be positive" in str(exc.value)


@pytest.mark.asyncio
async def test_ledger_mint_batch_partial_amounts(ledger: Ledger, wallet: Wallet):
    """Partial batch minting increases amount_issued step by step."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote.request)

    assert mint_quote.privkey

    # mint half of the quote
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([32], secrets, rs)
    sig = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)

    promises = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote.quote],
            quote_amounts=[32],
            outputs=outputs,
            signatures=[sig],
        )
    )
    assert len(promises) == 1

    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote and quote.amount_issued == 32
    assert quote.amount_paid == 64
    assert quote.state == MintQuoteState.paid

    # mint the remaining amount
    secrets2, rs2, derivation_paths2 = await wallet.generate_secrets_from_to(
        10001, 10001
    )
    outputs2, rs2 = wallet._construct_outputs([32], secrets2, rs2)
    sig2 = nut20.sign_mint_quote(mint_quote.quote, outputs2, mint_quote.privkey)

    promises2 = await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote.quote],
            quote_amounts=[32],
            outputs=outputs2,
            signatures=[sig2],
        )
    )
    assert len(promises2) == 1

    quote = await ledger.crud.get_mint_quote(quote_id=mint_quote.quote, db=ledger.db)
    assert quote and quote.amount_issued == 64
    assert quote.state == MintQuoteState.issued
    assert quote.issued_time is not None

    # nothing left to mint
    secrets3, rs3, derivation_paths3 = await wallet.generate_secrets_from_to(
        10002, 10002
    )
    outputs3, rs3 = wallet._construct_outputs([32], secrets3, rs3)
    sig3 = nut20.sign_mint_quote(mint_quote.quote, outputs3, mint_quote.privkey)

    with pytest.raises(Exception) as exc:
        await ledger.mint_batch(
            PostMintBatchRequest(
                quotes=[mint_quote.quote],
                quote_amounts=[32],
                outputs=outputs3,
                signatures=[sig3],
            )
        )
    assert "already issued" in str(exc.value)


@pytest.mark.asyncio
async def test_ledger_mint_partially_issued_quote_rejected(
    ledger: Ledger, wallet: Wallet
):
    """A quote partially issued via batch mint must not be minted again via the
    single-quote endpoint (which would issue more than was paid)."""
    await wallet.load_mint()
    mint_quote = await wallet.request_mint(64)

    await pay_if_regtest(mint_quote.request)

    assert mint_quote.privkey

    # partially mint via batch
    secrets, rs, derivation_paths = await wallet.generate_secrets_from_to(10000, 10000)
    outputs, rs = wallet._construct_outputs([32], secrets, rs)
    sig = nut20.sign_mint_quote(mint_quote.quote, outputs, mint_quote.privkey)
    await ledger.mint_batch(
        PostMintBatchRequest(
            quotes=[mint_quote.quote],
            quote_amounts=[32],
            outputs=outputs,
            signatures=[sig],
        )
    )

    # single mint of the full quote amount must be rejected
    secrets2, rs2, derivation_paths2 = await wallet.generate_secrets_from_to(
        10001, 10001
    )
    outputs2, rs2 = wallet._construct_outputs([64], secrets2, rs2)
    sig2 = nut20.sign_mint_quote(mint_quote.quote, outputs2, mint_quote.privkey)

    with pytest.raises(Exception) as exc:
        await ledger.mint(outputs=outputs2, quote_id=mint_quote.quote, signature=sig2)
    assert "partially issued" in str(exc.value)
