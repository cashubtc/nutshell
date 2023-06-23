import os
from datetime import datetime
from itertools import groupby, islice
from operator import itemgetter
from os import listdir
from os.path import isdir, join
from typing import Optional

from fastapi import APIRouter, Query

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
from .responses import (
    BalanceResponse,
    BurnResponse,
    InfoResponse,
    InvoiceResponse,
    InvoicesResponse,
    LockResponse,
    LocksResponse,
    PayResponse,
    PendingResponse,
    ReceiveResponse,
    SendResponse,
    SwapResponse,
    WalletsResponse,
)

router: APIRouter = APIRouter()


def create_wallet(
    url=settings.mint_url, dir=settings.cashu_dir, name=settings.wallet_name
):
    return Wallet(url, os.path.join(dir, name), name=name)


async def load_mint(wallet: Wallet, mint: Optional[str] = None):
    if mint:
        wallet = create_wallet(mint)
    await wallet.load_mint()
    return wallet


wallet = create_wallet()


@router.on_event("startup")
async def start_wallet():
    if settings.tor and not TorProxy().check_platform():
        raise Exception("tor not working.")
    await init_wallet(wallet)


@router.post("/pay", name="Pay lightning invoice", response_model=PayResponse)
async def pay(
    invoice: str = Query(default=..., description="Lightning invoice to pay"),
    mint: str = Query(
        default=None,
        description="Mint URL to pay from (None for default mint)",
    ),
):
    if not settings.lightning:
        raise Exception("lightning not enabled.")

    global wallet
    wallet = await load_mint(wallet, mint)

    total_amount, fee_reserve_sat = await wallet.get_pay_amount_with_fees(invoice)
    assert total_amount > 0, "amount has to be larger than zero."
    assert wallet.available_balance >= total_amount, "balance is too low."
    _, send_proofs = await wallet.split_to_send(wallet.proofs, total_amount)
    await wallet.pay_lightning(send_proofs, invoice, fee_reserve_sat)
    return PayResponse(
        amount=total_amount - fee_reserve_sat,
        fee=fee_reserve_sat,
        amount_with_fee=total_amount,
    )


@router.post(
    "/invoice", name="Request lightning invoice", response_model=InvoiceResponse
)
async def invoice(
    amount: int = Query(default=..., description="Amount to request in invoice"),
    hash: str = Query(default=None, description="Hash of paid invoice"),
    mint: str = Query(
        default=None,
        description="Mint URL to create an invoice at (None for default mint)",
    ),
    split: int = Query(
        default=None, description="Split minted tokens with a specific amount."
    ),
):
    # in case the user wants a specific split, we create a list of amounts
    optional_split = None
    if split:
        assert amount % split == 0, "split must be divisor or amount"
        assert amount >= split, "split must smaller or equal amount"
        n_splits = amount // split
        optional_split = [split] * n_splits
        print(f"Requesting split with {n_splits}*{split} sat tokens.")

    global wallet
    wallet = await load_mint(wallet, mint)
    if not settings.lightning:
        r = await wallet.mint(amount, split=optional_split)
        return InvoiceResponse(
            amount=amount,
        )
    elif amount and not hash:
        invoice = await wallet.request_mint(amount)
        return InvoiceResponse(
            amount=amount,
            invoice=invoice,
        )
    elif amount and hash:
        await wallet.mint(amount, split=optional_split, hash=hash)
        return InvoiceResponse(
            amount=amount,
            hash=hash,
        )
    return


@router.post(
    "/swap",
    name="Multi-mint swaps",
    summary="Swap funds between mints",
    response_model=SwapResponse,
)
async def swap(
    amount: int = Query(default=..., description="Amount to swap between mints"),
    outgoing_mint: str = Query(default=..., description="URL of outgoing mint"),
    incoming_mint: str = Query(default=..., description="URL of incoming mint"),
):
    if not settings.lightning:
        raise Exception("lightning not supported")
    incoming_wallet = await load_mint(wallet, mint=incoming_mint)
    outgoing_wallet = await load_mint(wallet, mint=outgoing_mint)
    if incoming_wallet.url == outgoing_wallet.url:
        raise Exception("mints for swap have to be different")

    # request invoice from incoming mint
    invoice = await incoming_wallet.request_mint(amount)

    # pay invoice from outgoing mint
    await outgoing_wallet.load_proofs()
    total_amount, fee_reserve_sat = await outgoing_wallet.get_pay_amount_with_fees(
        invoice.pr
    )
    assert total_amount > 0, "amount must be positive"
    if outgoing_wallet.available_balance < total_amount:
        raise Exception("balance too low")

    _, send_proofs = await outgoing_wallet.split_to_send(
        outgoing_wallet.proofs, total_amount, set_reserved=True
    )
    await outgoing_wallet.pay_lightning(send_proofs, invoice.pr, fee_reserve_sat)

    # mint token in incoming mint
    await incoming_wallet.mint(amount, hash=invoice.hash)
    await incoming_wallet.load_proofs()
    mint_balances = await incoming_wallet.balance_per_minturl()
    return SwapResponse(
        outgoing_mint=outgoing_mint,
        incoming_mint=incoming_mint,
        invoice=invoice,
        balances=mint_balances,
    )


@router.get(
    "/balance",
    name="Balance",
    summary="Display balance.",
    response_model=BalanceResponse,
)
async def balance():
    await wallet.load_proofs()
    keyset_balances = wallet.balance_per_keyset()
    mint_balances = await wallet.balance_per_minturl()
    return BalanceResponse(
        balance=wallet.available_balance, keysets=keyset_balances, mints=mint_balances
    )


@router.post("/send", name="Send tokens", response_model=SendResponse)
async def send_command(
    amount: int = Query(default=..., description="Amount to send"),
    nostr: str = Query(default=None, description="Send to nostr pubkey"),
    lock: str = Query(default=None, description="Lock tokens (P2SH)"),
    mint: str = Query(
        default=None,
        description="Mint URL to send from (None for default mint)",
    ),
    nosplit: bool = Query(
        default=False, description="Do not split tokens before sending."
    ),
):
    global wallet
    if not nostr:
        balance, token = await send(
            wallet, amount, lock, legacy=False, split=not nosplit
        )
        return SendResponse(balance=balance, token=token)
    else:
        token, pubkey = await send_nostr(wallet, amount, nostr)
        return SendResponse(balance=wallet.available_balance, token=token, npub=pubkey)


@router.post("/receive", name="Receive tokens", response_model=ReceiveResponse)
async def receive_command(
    token: str = Query(default=None, description="Token to receive"),
    lock: str = Query(default=None, description="Unlock tokens"),
    nostr: bool = Query(default=False, description="Receive tokens via nostr"),
    all: bool = Query(default=False, description="Receive all pending tokens"),
):
    initial_balance = wallet.available_balance
    if token:
        tokenObj: TokenV3 = deserialize_token_from_string(token)
        await verify_mints(wallet, tokenObj)
        balance = await receive(wallet, tokenObj, lock)
    elif nostr:
        await receive_nostr(wallet)
        balance = wallet.available_balance
    elif all:
        reserved_proofs = await get_reserved_proofs(wallet.db)
        balance = None
        if len(reserved_proofs):
            for _, value in groupby(reserved_proofs, key=itemgetter("send_id")):  # type: ignore
                proofs = list(value)
                token = await wallet.serialize_proofs(proofs)
                tokenObj = deserialize_token_from_string(token)
                await verify_mints(wallet, tokenObj)
                balance = await receive(wallet, tokenObj, lock)
    else:
        raise Exception("enter token or use either flag --nostr or --all.")
    assert balance
    return ReceiveResponse(initial_balance=initial_balance, balance=balance)


@router.post("/burn", name="Burn spent tokens", response_model=BurnResponse)
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
        raise Exception(
            "enter a token or use --all to burn all pending tokens, --force to check all tokens"
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
    return BurnResponse(balance=wallet.available_balance)


@router.get("/pending", name="Show pending tokens", response_model=PendingResponse)
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
            tokenObj = deserialize_token_from_string(token)
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
    return PendingResponse(pending_token=result)


@router.get("/lock", name="Generate receiving lock", response_model=LockResponse)
async def lock():
    p2shscript = await wallet.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    return LockResponse(P2SH=txin_p2sh_address)


@router.get("/locks", name="Show unused receiving locks", response_model=LocksResponse)
async def locks():
    locks = await get_unused_locks(db=wallet.db)
    return LocksResponse(locks=locks)


@router.get(
    "/invoices", name="List all pending invoices", response_model=InvoicesResponse
)
async def invoices():
    invoices = await get_lightning_invoices(db=wallet.db)
    return InvoicesResponse(invoices=invoices)


@router.get(
    "/wallets", name="List all available wallets", response_model=WalletsResponse
)
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
    return WalletsResponse(wallets=result)


@router.get("/info", name="Information about Cashu wallet", response_model=InfoResponse)
async def info():
    if settings.nostr_private_key:
        try:
            client = NostrClient(private_key=settings.nostr_private_key, connect=False)
            nostr_public_key = client.private_key.bech32()
            nostr_relays = settings.nostr_relays
        except:
            nostr_public_key = "Invalid key"
            nostr_relays = []
    else:
        nostr_public_key = None
        nostr_relays = []
    if settings.socks_host:
        socks_proxy = settings.socks_host + ":" + str(settings.socks_host)
    else:
        socks_proxy = None
    return InfoResponse(
        version=settings.version,
        wallet=wallet.name,
        debug=settings.debug,
        cashu_dir=settings.cashu_dir,
        mint_url=settings.mint_url,
        settings=settings.env_file,
        tor=settings.tor,
        nostr_public_key=nostr_public_key,
        nostr_relays=nostr_relays,
        socks_proxy=socks_proxy,
    )
