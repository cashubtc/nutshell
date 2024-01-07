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
from ...lightning.base import (
    InvoiceResponse,
    PaymentResponse,
    PaymentStatus,
    StatusResponse,
)
from ...nostr.client.client import NostrClient
from ...tor.tor import TorProxy
from ...wallet.crud import get_lightning_invoices, get_reserved_proofs
from ...wallet.helpers import (
    deserialize_token_from_string,
    init_wallet,
    list_mints,
    receive,
    send,
)
from ...wallet.nostr import receive_nostr, send_nostr
from ...wallet.wallet import Wallet as Wallet
from ..lightning.lightning import LightningWallet
from .api_helpers import verify_mints
from .responses import (
    BalanceResponse,
    BurnResponse,
    InfoResponse,
    InvoicesResponse,
    LockResponse,
    LocksResponse,
    PendingResponse,
    ReceiveResponse,
    RestoreResponse,
    SendResponse,
    SwapResponse,
    WalletsResponse,
)

router: APIRouter = APIRouter()


async def mint_wallet(
    mint_url: Optional[str] = None, raise_connection_error: bool = True
) -> LightningWallet:
    lightning_wallet = await LightningWallet.with_db(
        mint_url or settings.mint_url,
        db=os.path.join(settings.cashu_dir, settings.wallet_name),
        name=settings.wallet_name,
    )
    await lightning_wallet.async_init(raise_connection_error=raise_connection_error)
    return lightning_wallet


wallet = LightningWallet(
    settings.mint_url,
    db=os.path.join(settings.cashu_dir, settings.wallet_name),
    name=settings.wallet_name,
)


@router.on_event("startup")
async def start_wallet():
    global wallet
    wallet = await mint_wallet(settings.mint_url, raise_connection_error=False)
    if settings.tor and not TorProxy().check_platform():
        raise Exception("tor not working.")


@router.post(
    "/lightning/pay_invoice",
    name="Pay lightning invoice",
    response_model=PaymentResponse,
)
async def pay(
    bolt11: str = Query(default=..., description="Lightning invoice to pay"),
    mint: str = Query(
        default=None,
        description="Mint URL to pay from (None for default mint)",
    ),
) -> PaymentResponse:
    global wallet
    if mint:
        wallet = await mint_wallet(mint)
    payment_response = await wallet.pay_invoice(bolt11)
    ret = PaymentResponse(**payment_response.dict())
    ret.fee = None  # TODO: we can't return an Amount object, overwriting
    return ret


@router.get(
    "/lightning/payment_state",
    name="Request lightning invoice",
    response_model=PaymentStatus,
)
async def payment_state(
    payment_hash: str = Query(default=None, description="Id of paid invoice"),
    mint: str = Query(
        default=None,
        description="Mint URL to create an invoice at (None for default mint)",
    ),
) -> PaymentStatus:
    global wallet
    if mint:
        wallet = await mint_wallet(mint)
    state = await wallet.get_payment_status(payment_hash)
    return state


@router.post(
    "/lightning/create_invoice",
    name="Request lightning invoice",
    response_model=InvoiceResponse,
)
async def create_invoice(
    amount: int = Query(default=..., description="Amount to request in invoice"),
    mint: str = Query(
        default=None,
        description="Mint URL to create an invoice at (None for default mint)",
    ),
) -> InvoiceResponse:
    global wallet
    if mint:
        wallet = await mint_wallet(mint)
    invoice = await wallet.create_invoice(amount)
    return invoice


@router.get(
    "/lightning/invoice_state",
    name="Request lightning invoice",
    response_model=PaymentStatus,
)
async def invoice_state(
    payment_hash: str = Query(default=None, description="Payment hash of paid invoice"),
    mint: str = Query(
        default=None,
        description="Mint URL to create an invoice at (None for default mint)",
    ),
) -> PaymentStatus:
    global wallet
    if mint:
        wallet = await mint_wallet(mint)
    state = await wallet.get_invoice_status(payment_hash)
    return state


@router.get(
    "/lightning/balance",
    name="Balance",
    summary="Display balance.",
    response_model=StatusResponse,
)
async def lightning_balance() -> StatusResponse:
    try:
        await wallet.load_proofs(reload=True)
    except Exception as exc:
        return StatusResponse(error_message=str(exc), balance=0)
    return StatusResponse(error_message=None, balance=wallet.available_balance * 1000)


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
    incoming_wallet = await mint_wallet(incoming_mint)
    outgoing_wallet = await mint_wallet(outgoing_mint)
    if incoming_wallet.url == outgoing_wallet.url:
        raise Exception("mints for swap have to be different")

    # request invoice from incoming mint
    invoice = await incoming_wallet.request_mint(amount)

    # pay invoice from outgoing mint
    await outgoing_wallet.load_proofs(reload=True)
    quote = await outgoing_wallet.get_pay_amount_with_fees(invoice.bolt11)
    total_amount = quote.amount + quote.fee_reserve
    if outgoing_wallet.available_balance < total_amount:
        raise Exception("balance too low")

    _, send_proofs = await outgoing_wallet.split_to_send(
        outgoing_wallet.proofs, total_amount, set_reserved=True
    )
    await outgoing_wallet.pay_lightning(
        send_proofs, invoice.bolt11, quote.fee_reserve, quote.quote
    )

    # mint token in incoming mint
    await incoming_wallet.mint(amount, id=invoice.id)
    await incoming_wallet.load_proofs(reload=True)
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
    await wallet.load_proofs(reload=True)
    keyset_balances = wallet.balance_per_keyset()
    mint_balances = await wallet.balance_per_minturl()
    return BalanceResponse(
        balance=wallet.available_balance, keysets=keyset_balances, mints=mint_balances
    )


@router.post("/send", name="Send tokens", response_model=SendResponse)
async def send_command(
    amount: int = Query(default=..., description="Amount to send"),
    nostr: str = Query(default=None, description="Send to nostr pubkey"),
    lock: str = Query(default=None, description="Lock tokens (P2PK)"),
    mint: str = Query(
        default=None,
        description="Mint URL to send from (None for default mint)",
    ),
    nosplit: bool = Query(
        default=False, description="Do not split tokens before sending."
    ),
):
    global wallet
    if mint:
        wallet = await mint_wallet(mint)
    if not nostr:
        balance, token = await send(
            wallet, amount=amount, lock=lock, legacy=False, split=not nosplit
        )
        return SendResponse(balance=balance, token=token)
    else:
        token, pubkey = await send_nostr(wallet, amount=amount, pubkey=nostr)
        return SendResponse(balance=wallet.available_balance, token=token, npub=pubkey)


@router.post("/receive", name="Receive tokens", response_model=ReceiveResponse)
async def receive_command(
    token: str = Query(default=None, description="Token to receive"),
    nostr: bool = Query(default=False, description="Receive tokens via nostr"),
    all: bool = Query(default=False, description="Receive all pending tokens"),
):
    wallet = await mint_wallet()
    initial_balance = wallet.available_balance
    if token:
        tokenObj: TokenV3 = deserialize_token_from_string(token)
        await verify_mints(wallet, tokenObj)
        balance = await receive(wallet, tokenObj)
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
                balance = await receive(wallet, tokenObj)
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
        wallet = await mint_wallet(mint)
    if not (all or token or force or delete) or (token and all):
        raise Exception(
            "enter a token or use --all to burn all pending tokens, --force to"
            " check all tokens or --delete with send ID to force-delete pending"
            " token from list if mint is unavailable.",
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
        await wallet.invalidate(proofs)
    else:
        await wallet.invalidate(proofs, check_spendable=True)
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
                    key=itemgetter("send_id"),  # type: ignore
                )
            ),
            offset,
            number,
        ):
            grouped_proofs = list(value)
            token = await wallet.serialize_proofs(grouped_proofs)
            tokenObj = deserialize_token_from_string(token)
            mint = [t.mint for t in tokenObj.token if t.mint][0]
            reserved_date = datetime.utcfromtimestamp(
                int(grouped_proofs[0].time_reserved)  # type: ignore
            ).strftime("%Y-%m-%d %H:%M:%S")
            result.update({
                f"{i}": {
                    "amount": sum_proofs(grouped_proofs),
                    "time": reserved_date,
                    "ID": key,
                    "token": token,
                    "mint": mint,
                }
            })
    return PendingResponse(pending_token=result)


@router.get("/lock", name="Generate receiving lock", response_model=LockResponse)
async def lock():
    pubkey = await wallet.create_p2pk_pubkey()
    return LockResponse(P2PK=pubkey)


@router.get("/locks", name="Show unused receiving locks", response_model=LocksResponse)
async def locks():
    pubkey = await wallet.create_p2pk_pubkey()
    return LocksResponse(locks=[pubkey])


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
                    result.update({
                        f"{w}": {
                            "balance": sum_proofs(wallet.proofs),
                            "available": sum_proofs([
                                p for p in wallet.proofs if not p.reserved
                            ]),
                        }
                    })
        except Exception:
            pass
    return WalletsResponse(wallets=result)


@router.post("/v1/restore", name="Restore wallet", response_model=RestoreResponse)
async def restore(
    to: int = Query(default=..., description="Counter to which restore the wallet"),
):
    if to < 0:
        raise Exception("Counter must be positive")
    await wallet.load_mint()
    await wallet.restore_promises_from_to(0, to)
    await wallet.invalidate(wallet.proofs, check_spendable=True)
    return RestoreResponse(balance=wallet.available_balance)


@router.get("/info", name="Information about Cashu wallet", response_model=InfoResponse)
async def info():
    if settings.nostr_private_key:
        try:
            client = NostrClient(private_key=settings.nostr_private_key, connect=False)
            nostr_public_key = client.private_key.bech32()
            nostr_relays = settings.nostr_relays
        except Exception:
            nostr_public_key = "Invalid key"
            nostr_relays = []
    else:
        nostr_public_key = None
        nostr_relays = []
    mint_list = await list_mints(wallet)
    return InfoResponse(
        version=settings.version,
        wallet=wallet.name,
        debug=settings.debug,
        cashu_dir=settings.cashu_dir,
        mint_urls=mint_list,
        settings=settings.env_file,
        tor=settings.tor,
        nostr_public_key=nostr_public_key,
        nostr_relays=nostr_relays,
        socks_proxy=settings.socks_proxy,
    )
