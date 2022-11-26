import asyncio
import base64
import logging
import json
import os
from typing import Optional, List, Dict, Tuple
from pydantic import BaseModel, PositiveInt, Field, SecretStr
from fastapi import HTTPException, status, APIRouter, Path, Query
from pathlib import Path
from operator import itemgetter
from itertools import groupby
from datetime import datetime
from cashu.core.base import Proof
from cashu.core.helpers import sum_proofs
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.crud import (
    get_lightning_invoices,
    get_reserved_proofs,
    get_unused_locks,
)
from cashu.wallet.wallet import Wallet as Wallet
from cashu.core.settings import MINT_URL, MINT_HOST, CASHU_DIR, LIGHTNING


logger = logging.getLogger(__name__)

app = APIRouter(prefix="/v0/wallet")


async def init_wallet(wallet_c: Wallet):
    """Performs migrations and loads proofs from db."""
    await migrate_databases(wallet_c.db, migrations)
    await wallet_c.load_proofs()


wallet: Wallet = Wallet(
    url=MINT_URL,
    db=str(Path(CASHU_DIR) / "default"),
)


@app.on_event("startup")
async def start_wallet():
    """Starts wallet on startup."""
    await init_wallet(wallet)
    await wallet.load_mint()
    logger.info("Wallet started")


@app.on_event("shutdown")
async def shutdown_tor():
    """Shutdowns wallet on shutdown."""
    if wallet.tor.tor_running:
        logger.info("Stopping Tor")
        wallet.tor.stop_daemon()
    logger.info("Wallet shutdown")


@app.get("/health")
async def health():
    """Health check"""
    return {"status": "OK"}


@app.post("/lightning/pay")
async def pay_to_lightning_invoice(invoice: str):
    """Pay to a lightning invoice using mint tokens."""
    if not LIGHTNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lightning is not enabled.",
        )
    logger.info(f"Wallet status: {wallet.status()}")
    amount, fees = await wallet.get_pay_amount_with_fees(invoice)
    if amount <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Amount must be greater than 0.",
        )
    if amount + fees > wallet.available_balance:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient funds.",
        )
    _, send_proofs = await wallet.split_to_send(wallet.proofs, amount)
    await wallet.pay_lightning(send_proofs, invoice)
    logger.info(f"Wallet status: {wallet.status()}")
    return {"amount": amount, "fees": fees}


@app.get("/lightning/invoice")
async def generate_lightning_invoice(
    amount: PositiveInt = Query(..., description="Amount to pay in the mint in satoshis."),
):
    """Generate a lightning invoice to deposit in satoshis in the mint."""
    if not LIGHTNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lightning is not enabled.",
        )
    logger.info(f"Wallet status: {wallet.status()}")
    invoice = await wallet.request_mint(amount=amount)
    if invoice.pr:
        logger.info(f"Invoice created for amount {amount}")
        logger.info(f"Invoice {invoice.pr} - invoice hash {invoice.hash}")
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error creating invoice.",
        )
    return {"invoice": invoice, "amount": amount}


@app.put("/lightning/claim")
async def claim(
    amount: int = Query(..., gt=0, description="Amount to receive in satoshis."),
    description_hash: str = Query(..., description="Hash of the paid invoice."),
    unhashed_description: Optional[str] = Query(None, description="Paid invoice description."),
):
    """Claim tokens from a paid lightning invoice."""
    if not LIGHTNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Lightning is not enabled.",
        )
    logger.info(f"Wallet status: {wallet.status()}")
    try:
        proofs = await wallet.mint(amount=amount, payment_hash=description_hash)
    except Exception as e:
        if "Invoice already paid" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invoice already paid.",
            )
        elif "Lightning invoice not paid yet." in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Lightning invoice not paid yet.",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Error receiving lightning payment.",
            )
    logger.info(f"Wallet status: {wallet.status()}")
    return {"amount": amount, "proofs": proofs}


@app.get("/balance")
async def get_balance():
    """Get the wallet balance."""

    class Balance(BaseModel):
        available_balance: int = Field(0, description="Available balance")
        total_balance: int = Field(0, description="Including pending tokens")
        key_sets_balances: dict[str, float] = Field({}, description="Key sets balances")

    balance = Balance()
    balance.key_sets_balances = wallet.balance_per_keyset()
    balance.available_balance = wallet.available_balance
    balance.total_balance = wallet.balance

    return balance


@app.post("/send")
async def send(
    amount: int = Query(..., description="Amount to send", gt=0),
    lock: str | None = Query(None, description="Destination address", min_length=22),
):
    """Send mint tokens."""
    if amount > wallet.available_balance:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Insufficient funds.",
        )
    logger.info(f"Wallet status: {wallet.status()}")
    p2sh = False
    if lock:
        if len(lock.split("P2SH:")) == 2:
            p2sh = True
    _, send_proofs = await wallet.split_to_send(
        proofs=wallet.proofs, amount=amount, scnd_secret=lock, set_reserved=True
    )
    mint_token = await wallet.serialize_proofs(proofs=send_proofs, hide_secrets=True if lock and not p2sh else False)
    logger.info(f"Wallet status: {wallet.status()}")
    return {"amount": amount, "tokens": mint_token}


@app.post("/receive")
async def receive(
    token: str = Query(..., description="Token to receive"),
    lock: str | None = Query(None, description="Destination address", min_length=22),
):
    """Receive mint tokens."""
    logger.info(f"Wallet status: {wallet.status()}")
    if lock:
        if len(lock.split("P2SH:")) == 2:
            address = lock.split("P2SH:")[1]
            p2sh_scripts = await get_unused_locks(address=address, db=wallet.db)
            script = p2sh_scripts[0].script
            signature = p2sh_scripts[0].signature
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid lock format. Expected P2SH:<address>",
            )
    else:
        script = None
        signature = None
    proofs = [Proof(**proof) for proof in json.loads(base64.urlsafe_b64decode(token))]
    first_proofs, second_proofs = await wallet.redeem(proofs=proofs, scnd_script=script, scnd_siganture=signature)
    return {
        "proofs": {"first": first_proofs, "second": second_proofs},
    }


@app.post("/burn")
async def burn(
    token: str | None = Query(None, description="Token to burn"),
    all_tokens: bool = Query(False, description="Burn all spent tokens"),
    force: bool = Query(False, description="Force check on all token"),
):
    """Burn spent tokens."""
    logger.info(f"Wallet status: {wallet.status()}")
    if all_tokens:
        logger.info("Burn all spent tokens")
        proofs = get_reserved_proofs(wallet.db)
    elif force:
        # check all proofs in db
        logger.info("Force check on all token")
        proofs = wallet.proofs
    elif token:
        logger.info(f"Burn token - {token}")
        proofs = [Proof(**proof) for proof in json.loads(base64.urlsafe_b64decode(token))]
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request. Please provide a token or set all_tokens to True.",
        )
    await wallet.invalidate(proofs=proofs)
    return {"proofs": proofs}


@app.get("/pending")
async def get_pending():
    """Get pending tokens."""

    class Pending(BaseModel):
        amount: int = Field(..., description="Amount of pending tokens in sats")
        reserved_date: str = Field(..., description="Date of reservation (UTC) in format YYYY-MM-DD HH:MM:SS")
        id: str = Field(..., description="ID of the token")
        mint_token_with_secret: SecretStr = Field(..., description="Secret")
        mint_token: str = Field(..., description="Token")

    reserved_proofs = await get_reserved_proofs(wallet.db)
    list_of_pending = []
    if len(reserved_proofs) > 0:
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))
        for i, (key, value) in enumerate(groupby(sorted_proofs, key=itemgetter("send_id"))):
            grouped_proofs = list(value)
            mint_token = await wallet.serialize_proofs(grouped_proofs)
            token_hidden_secret = await wallet.serialize_proofs(grouped_proofs, hide_secrets=True)
            reserved_date = datetime.utcfromtimestamp(grouped_proofs[0].reserved_date).strftime("%Y-%m-%d %H:%M:%S")
            list_of_pending.append(
                Pending(
                    amount=sum_proofs(grouped_proofs),
                    reserved_date=reserved_date,
                    id=key,
                    mint_token_with_secret=SecretStr(token_hidden_secret),
                    mint_token=mint_token,
                )
            )
    return list_of_pending


@app.put("/lock")
async def generate_lock():
    """
    Generate lock to receive tokens.
    Anyone can send to this address but only the owner can spend the tokens.
        - To send to this address, use the /send endpoint.
        - To spend the tokens, use the /receive endpoint.
        (specify the lock address in the lock parameter)
    """
    p2shscript = await wallet.create_p2sh_lock()
    return {"script": p2shscript.script}


@app.get("/locks")
async def get_locks():
    """Get all unused locks."""
    locks = await get_unused_locks(db=wallet.db)
    if len(locks) > 0:
        logger.info(f"Found {len(locks)} unused locks")
        return {"unused_locks": locks}
    else:
        logger.info("No unused locks found")
        return {"unused_locks": []}


@app.get("/invoices")
async def get_invoices():
    """Get all pending invoices."""
    invoices = await get_lightning_invoices(db=wallet.db)
    if len(invoices) > 0:
        logger.info(f"Found {len(invoices)} invoices")
        return {"invoices": invoices}
    else:
        logger.info("No invoices found")
        return {"invoices": []}


@app.get("/wallets")
async def get_wallets() -> Dict[str, List[Tuple[Wallet, bool]]]:
    """Get all wallets with non-zero balance.

    Returns:
        Dict[str, List[Tuple[Wallet, bool]]]: Dict of wallets with non-zero balance.
            Tuple contains the wallet and a boolean indicating if the wallet the active wallet.
    """
    wallets = [str(d) for d in os.listdir(CASHU_DIR) if (Path(CASHU_DIR) / str(d)).is_dir()]
    logger.info(f"Found {len(wallets)} - {wallets=}")
    try:
        wallets.remove("mint")
    except ValueError:
        pass
    wallets_model = []
    for w in wallets:
        active_wallet = False
        temp_wallet = Wallet(
            url=MINT_URL,
            db=str(Path(CASHU_DIR) / w),
        )
        try:
            await init_wallet(temp_wallet)
            if temp_wallet.proofs and len(temp_wallet.proofs) > 0:
                if temp_wallet == wallet:
                    active_wallet = True
                wallets_model.append((temp_wallet, active_wallet))
        except Exception as e:
            logger.error(f"Error loading wallet {w}: {e}")
    logger.info(f"Found {len(wallets_model)} wallets with non-zero balance - {wallets_model=}")
    return {"wallets": wallets_model}
