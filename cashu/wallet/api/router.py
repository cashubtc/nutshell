import os
from datetime import datetime
from itertools import groupby, islice
from operator import itemgetter
from os import listdir
from os.path import isdir, join
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, status

from ...core.base import TokenV3
from ...core.helpers import sum_proofs
from ...core.settings import settings
from ...nostr.nostr.client.client import NostrClient
from ...tor.tor import TorProxy
from ...wallet.crud import get_lightning_invoices, get_reserved_proofs, get_unused_locks
from ...wallet.helpers import deserialize_token_from_string, init_wallet, receive, send
from ...wallet.nostr import receive_nostr, send_nostr
from ...wallet.wallet import Wallet as Wallet
from .api_helpers import verify_mints

router: APIRouter = APIRouter()


def create_wallet(url=settings.mint_url, dir=settings.cashu_dir, name="wallet"):
    return Wallet(url, os.path.join(dir, name), name=name)


async def load_mint(wallet: Wallet, mint: Optional[str] = None):
    if mint:
        wallet = create_wallet(mint)
    try:
        await wallet.load_mint()
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    return wallet


wallet = create_wallet()


@router.on_event("startup")
async def start_wallet():
    if settings.tor and not TorProxy().check_platform():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="tor not working"
        )
    await init_wallet(wallet)


@router.post("/pay", name="Pay lightning invoice")
async def pay(
    invoice: str = Query(default=..., description="Lightning invoice to pay"),
    mint: str = Query(
        default=None,
        description="Mint URL to pay from (None for default mint)",
    ),
):
    if not settings.lightning:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="lightning not enabled."
        )
    global wallet
    wallet = await load_mint(wallet, mint)

    await wallet.load_proofs()
    initial_balance = wallet.available_balance
    total_amount, fee_reserve_sat = await wallet.get_pay_amount_with_fees(invoice)
    assert total_amount > 0, HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="amount has to be larger than zero.",
    )
    if wallet.available_balance < total_amount:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="balance is too low."
        )
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    await wallet.pay_lightning(send_proofs, invoice, fee_reserve_sat)
    await wallet.load_proofs()
    return {
        "amount": total_amount - fee_reserve_sat,
        "fee": fee_reserve_sat,
        "amount_with_fee": total_amount,
        "initial_balance": initial_balance,
        "balance": wallet.available_balance,
    }


@router.post("/invoice", name="Request lightning invoice")
async def invoice(
    amount: int = Query(default=..., description="Amount to request in invoice"),
    hash: str = Query(default=None, description="Hash of paid invoice"),
    mint: str = Query(
        default=None,
        description="Mint URL to create an invoice at (None for default mint)",
    ),
):
    global wallet
    wallet = await load_mint(wallet, mint)
    initial_balance = wallet.available_balance
    if not settings.lightning:
        r = await wallet.mint(amount)
        return {
            "amount": amount,
            "balance": wallet.available_balance,
            "initial_balance": initial_balance,
        }
    elif amount and not hash:
        invoice = await wallet.request_mint(amount)
        return {
            "invoice": invoice,
            "balance": wallet.available_balance,
            "initial_balance": initial_balance,
        }
    elif amount and hash:
        await wallet.mint(amount, hash)
        return {
            "amount": amount,
            "hash": hash,
            "balance": wallet.available_balance,
            "initial_balance": initial_balance,
        }
    return


@router.get("/balance", name="Balance", summary="Display balance.")
async def balance():
    await wallet.load_proofs()
    result: dict = {"balance": wallet.available_balance}
    keyset_balances = wallet.balance_per_keyset()
    if len(keyset_balances) > 0:
        result.update({"keysets": keyset_balances})
    mint_balances = await wallet.balance_per_minturl()
    if len(mint_balances) > 0:
        result.update({"mints": mint_balances})

    return result


@router.post("/send", name="Send tokens")
async def send_command(
    amount: int = Query(default=..., description="Amount to send"),
    nostr: str = Query(default=None, description="Send to nostr pubkey"),
    lock: str = Query(default=None, description="Lock tokens (P2SH)"),
    mint: str = Query(
        default=None,
        description="Mint URL to send from (None for default mint)",
    ),
):
    global wallet
    wallet = await load_mint(wallet, mint)

    await wallet.load_proofs()
    if not nostr:
        try:
            balance, token = await send(wallet, amount, lock, legacy=False)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        return {"balance": balance, "token": token}
    else:
        try:
            token, pubkey = await send_nostr(wallet, amount, nostr)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        return {
            "balance": wallet.available_balance,
            "token": token,
            "npub": pubkey,
        }


@router.post("/receive", name="Receive tokens")
async def receive_command(
    token: str = Query(default=None, description="Token to receive"),
    lock: str = Query(default=None, description="Unlock tokens"),
    nostr: bool = Query(default=False, description="Receive tokens via nostr"),
    all: bool = Query(default=False, description="Receive all pending tokens"),
):
    result = {"initial_balance": wallet.available_balance}
    if token:
        try:
            tokenObj: TokenV3 = await deserialize_token_from_string(token)

            try:
                await verify_mints(wallet, tokenObj)
            except Exception as e:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                )

            balance = await receive(wallet, tokenObj, lock)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    elif nostr:
        try:
            await receive_nostr(wallet)
            balance = wallet.available_balance
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    elif all:
        reserved_proofs = await get_reserved_proofs(wallet.db)
        balance = None
        if len(reserved_proofs):
            for _, value in groupby(reserved_proofs, key=itemgetter("send_id")):  # type: ignore
                proofs = list(value)
                token = await wallet.serialize_proofs(proofs)
                tokenObj = await deserialize_token_from_string(token)
                try:
                    await verify_mints(wallet, tokenObj)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                    )
                try:
                    balance = await receive(wallet, tokenObj, lock)
                except Exception as e:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
                    )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="enter token or use either flag --nostr or --all.",
        )
    assert balance
    result.update({"balance": balance})
    return result


@router.post("/burn", name="Burn spent tokens")
async def burn(
    token: str = Query(default=None, description="Token to burn"),
    all: bool = Query(default=False, description="Burn all spent tokens"),
    force: bool = Query(default=False, description="Force check on all tokens."),
    delete: str = Query(
        default=None,
        description="Forcefully delete pending token by send ID if mint is unavailable",
    ),
    mint: str = Query(
        default=None,
        description="Mint URL to burn from (None for default mint)",
    ),
):
    global wallet
    if not delete:
        wallet = await load_mint(wallet, mint)
    if not (all or token or force or delete) or (token and all):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="enter a token or use --all to burn all pending tokens, --force to check all tokens"
            "or --delete with send ID to force-delete pending token from list if mint is unavailable.",
        )
    if all:
        # check only those who are flagged as reserved
        proofs = await get_reserved_proofs(wallet.db)
    elif force:
        # check all proofs in db
        proofs = wallet.proofs
    elif delete:
        reserved_proofs = await get_reserved_proofs(wallet.db)
        proofs = [proof for proof in reserved_proofs if proof["send_id"] == delete]
    else:
        # check only the specified ones
        tokenObj = TokenV3.deserialize(token)
        proofs = tokenObj.get_proofs()

    if delete:
        await wallet.invalidate(proofs, check_spendable=False)
    else:
        await wallet.invalidate(proofs)
    return {"balance": wallet.available_balance}


@router.get("/pending", name="Show pending tokens")
async def pending(
    number: int = Query(default=None, description="Show only n pending tokens"),
    offset: int = Query(
        default=0, description="Show pending tokens only starting from offset"
    ),
):
    reserved_proofs = await get_reserved_proofs(wallet.db)
    result: dict = {}
    if len(reserved_proofs):
        sorted_proofs = sorted(reserved_proofs, key=itemgetter("send_id"))  # type: ignore
        if number:
            number += offset
        for i, (key, value) in islice(
            enumerate(
                groupby(
                    sorted_proofs,
                    key=itemgetter("send_id"),
                )
            ),
            offset,
            number,
        ):
            grouped_proofs = list(value)
            token = await wallet.serialize_proofs(grouped_proofs)
            tokenObj = await deserialize_token_from_string(token)
            mint = [t.mint for t in tokenObj.token][0]
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)
            ).strftime("%Y-%m-%d %H:%M:%S")
            result.update(
                {
                    f"{i}": {
                        "amount": sum_proofs(grouped_proofs),
                        "time": reserved_date,
                        "ID": key,
                        "token": token,
                        "mint": mint,
                    }
                }
            )
    return result


@router.get("/lock", name="Generate receiving lock")
async def lock():
    p2shscript = await wallet.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    return {"P2SH": txin_p2sh_address}


@router.get("/locks", name="Show unused receiving locks")
async def locks():
    locks = await get_unused_locks(db=wallet.db)
    if len(locks):
        return {"locks": locks}
    else:
        return {"locks": []}


@router.get("/invoices", name="List all pending invoices")
async def invoices():
    invoices = await get_lightning_invoices(db=wallet.db)
    if len(invoices):
        return {"invoices": invoices}
    else:
        return {"invoices": []}


@router.get("/wallets", name="List all available wallets")
async def wallets():
    wallets = [
        d for d in listdir(settings.cashu_dir) if isdir(join(settings.cashu_dir, d))
    ]
    try:
        wallets.remove("mint")
    except ValueError:
        pass
    result = {}
    for w in wallets:
        wallet = Wallet(settings.mint_url, os.path.join(settings.cashu_dir, w), name=w)
        try:
            await init_wallet(wallet)
            if wallet.proofs and len(wallet.proofs):
                active_wallet = False
                if w == wallet.name:
                    active_wallet = True
                if active_wallet:
                    result.update(
                        {
                            f"{w}": {
                                "balance": sum_proofs(wallet.proofs),
                                "available": sum_proofs(
                                    [p for p in wallet.proofs if not p.reserved]
                                ),
                            }
                        }
                    )
        except:
            pass
    return result


@router.get("/info", name="Information about Cashu wallet")
async def info():
    general = {
        "version": settings.version,
        "wallet": wallet.name,
        "debug": settings.debug,
        "cashu_dir": settings.cashu_dir,
        "mint_url": settings.mint_url,
    }
    if settings.env_file:
        general.update({"settings": settings.env_file})
    if settings.tor:
        general.update({"tor": settings.tor})
    if settings.nostr_private_key:
        try:
            client = NostrClient(private_key=settings.nostr_private_key, connect=False)
            general.update(
                {
                    "nostr": {
                        "public_key": client.private_key.bech32(),
                        "relays": settings.nostr_relays,
                    },
                }
            )
        except:
            general.update({"nostr": "Invalid key"})
    if settings.socks_host:
        general.update(
            {"socks proxy": settings.socks_host + ":" + str(settings.socks_host)}
        )

    return general
