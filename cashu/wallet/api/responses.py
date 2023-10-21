from typing import Dict, List, Optional

from pydantic import BaseModel

from ...core.base import Invoice


class PayResponse(BaseModel):
    ok: Optional[bool] = None


class InvoiceResponse(BaseModel):
    amount: Optional[int] = None
    invoice: Optional[Invoice] = None
    id: Optional[str] = None


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
    P2PK: Optional[str]


class LocksResponse(BaseModel):
    locks: List[str]


class InvoicesResponse(BaseModel):
    invoices: List[Invoice]


class WalletsResponse(BaseModel):
    wallets: Dict


class RestoreResponse(BaseModel):
    balance: int


class InfoResponse(BaseModel):
    version: str
    wallet: str
    debug: bool
    cashu_dir: str
    mint_urls: List[str] = []
    settings: Optional[str]
    tor: bool
    nostr_public_key: Optional[str] = None
    nostr_relays: List[str] = []
    socks_proxy: Optional[str] = None
