from typing import Dict, List, Optional

from pydantic import BaseModel

from ...core.base import Invoice, P2SHScript


class PayResponse(BaseModel):
    amount: int
    fee: int
    amount_with_fee: int


class InvoiceResponse(BaseModel):
    amount: Optional[int] = None
    invoice: Optional[Invoice] = None
    hash: Optional[str] = None


class SwapResponse(BaseModel):
    outgoing_mint: str
    incoming_mint: str
    invoice: Invoice
    balances: Dict


class BalanceResponse(BaseModel):
    balance: int
    keysets: Optional[Dict] = None
    mints: Optional[Dict] = None


class SendResponse(BaseModel):
    balance: int
    token: str
    npub: Optional[str] = None


class ReceiveResponse(BaseModel):
    initial_balance: int
    balance: int


class BurnResponse(BaseModel):
    balance: int


class PendingResponse(BaseModel):
    pending_token: Dict


class LockResponse(BaseModel):
    P2SH: Optional[str]


class LocksResponse(BaseModel):
    locks: List[P2SHScript]


class InvoicesResponse(BaseModel):
    invoices: List[Invoice]


class WalletsResponse(BaseModel):
    wallets: Dict


class InfoResponse(BaseModel):
    version: str
    wallet: str
    debug: bool
    cashu_dir: str
    mint_url: str
    settings: Optional[str]
    tor: bool
    nostr_public_key: Optional[str] = None
    nostr_relays: List[str] = []
    socks_proxy: Optional[str] = None
