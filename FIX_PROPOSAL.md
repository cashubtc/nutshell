**Security Fix: Early Return in Mint Tasks Skips Validation**

### Vulnerable Code
The vulnerable code is located in `cashu/mint/tasks.py` at line 53:
```python
async def _process_invoice_callback(
    checking_id: str,
    conn: Connection | None = None,
):
    # ...
    quote = await get_quote_byCheckId(
        checking_id=checking_id, db=self.db, conn=conn
    )
    if not quote:
        logger.error(f"Quote not found for {checking_id}")
        return  # ← VULNERABLE: Early return without proper handling
```

### Recommended Fix
To fix the vulnerability, update the code to handle the case when a quote is not found:
```python
if not quote:
    logger.error(f"Quote not found for {checking_id}")
    # Update state to reflect error
    await mark_invoice_as_failed(checking_id)
    # Notify administrators
    await notify_admin(f"Invalid checking_id: {checking_id}")
    return
```

### Complete Fixed Code
The complete fixed code for the `_process_invoice_callback` function:
```python
async def _process_invoice_callback(
    checking_id: str,
    conn: Connection | None = None,
):
    # ...
    quote = await get_quote_byCheckId(
        checking_id=checking_id, db=self.db, conn=conn
    )
    if not quote:
        logger.error(f"Quote not found for {checking_id}")
        await mark_invoice_as_failed(checking_id)
        await notify_admin(f"Invalid checking_id: {checking_id}")
        return
    # ... (rest of the function remains the same)
```

### Example Use Case
To test the fix, create a test case where a quote is not found for a given `checking_id`. Verify that the state is updated correctly and an error notification is sent to administrators.

### Commit Message
```
Fix security vulnerability: Early return in mint tasks skips validation

* Update state to reflect error when quote is not found
* Notify administrators of invalid checking_id
```