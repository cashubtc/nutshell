"""Tests for invoice callback quote-not-found handling (Issue #929)."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_missing_quote_raises_error():
    """invoice_callback_dispatcher should raise ValueError when quote not found."""
    from cashu.mint.tasks import LedgerTasks

    # Create a mock LedgerTasks instance
    ledger = MagicMock(spec=LedgerTasks)
    ledger.db = MagicMock()
    ledger.crud = MagicMock()
    ledger.crud.get_mint_quote = AsyncMock(return_value=None)
    ledger.events = MagicMock()

    # Mock the connection context manager
    mock_conn = AsyncMock()
    ledger.db.get_connection = MagicMock(return_value=mock_conn)
    mock_conn.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    # Call the actual method with the mock instance
    with pytest.raises(ValueError, match="Quote not found"):
        await LedgerTasks.invoice_callback_dispatcher(ledger, "nonexistent_id")


@pytest.mark.asyncio
async def test_valid_quote_processes_normally():
    """invoice_callback_dispatcher should process valid quotes without error."""
    from cashu.mint.tasks import LedgerTasks

    ledger = MagicMock(spec=LedgerTasks)
    ledger.db = MagicMock()
    ledger.crud = MagicMock()
    ledger.events = MagicMock()
    ledger.events.submit = AsyncMock()

    mock_quote = MagicMock()
    mock_quote.unpaid = True
    ledger.crud.get_mint_quote = AsyncMock(return_value=mock_quote)
    ledger.crud.update_mint_quote = AsyncMock()

    mock_conn = AsyncMock()
    ledger.db.get_connection = MagicMock(return_value=mock_conn)
    mock_conn.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_conn.__aexit__ = AsyncMock(return_value=False)

    # Should not raise
    await LedgerTasks.invoice_callback_dispatcher(ledger, "valid_id")
    ledger.events.submit.assert_called_once()
