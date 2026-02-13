from typing import Any, Dict, List, Optional

import httpx

from cashu.core.base import MintQuoteState
from cashu.core.nostr import create_nip98_header, derive_nostr_keypair, get_npub
from cashu.core.settings import settings
from cashu.wallet.crud import get_bolt11_mint_quote
from cashu.wallet.wallet import Wallet


# Constant holding the npub cash hostname
NPUB_CASH = settings.npub_cash_hostname

class NpubCash:
    """Client for npub.cash API"""
    
    API_URL = f"https://{NPUB_CASH}/api/v2"
    LNURL_BASE = f"https://{NPUB_CASH}/.well-known/lnurlp"

    def __init__(self, wallet: Wallet):
        self.wallet = wallet
        self.privkey_hex: Optional[str] = None
        self.pubkey_hex: Optional[str] = None
        self.npub: Optional[str] = None
        if self.wallet.seed:
            self._derive_keys()

    def _derive_keys(self):
        """Derives Nostr keys from wallet seed."""
        if not self.wallet.seed:
             raise ValueError("Wallet seed not initialized")
        self.privkey_hex, self.pubkey_hex = derive_nostr_keypair(self.wallet.seed)
        assert self.pubkey_hex
        self.npub = get_npub(self.pubkey_hex)

    async def _request(self, method: str, path: str, body: Optional[Dict] = None, auth: bool = True) -> Any:
        """Executes an HTTP request with optional NIP-98 authentication."""
        url = f"{self.API_URL}{path}"
        headers: Dict[str, str] = {}
        
        if auth:
            if not self.privkey_hex:
                 self._derive_keys()
            if not self.privkey_hex:
                 raise ValueError("Private key not initialized. Cannot authenticate.")
            headers["Authorization"] = create_nip98_header(url, method, self.privkey_hex, body)
            
        async with httpx.AsyncClient() as client:
            try:
                if method == "GET":
                    resp = await client.get(url, headers=headers)
                elif method == "PUT":
                    resp = await client.put(url, headers=headers, json=body)
                elif method == "PATCH":
                    resp = await client.patch(url, headers=headers, json=body)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                resp.raise_for_status()
                data = resp.json()
                
                if data.get("error"):
                    raise Exception(data.get("message", "Unknown error"))
                    
                return data.get("data", {})
            except httpx.HTTPStatusError as e:
                try:
                    error_data = e.response.json()
                    if error_data.get("error"):
                        raise Exception(error_data.get("message", str(e)))
                except Exception:
                    pass
                raise e

    async def get_lnurl(self) -> str:
        """Returns the Lightning Address."""
        if not self.npub:
            self._derive_keys()
        return f"{self.npub}@{NPUB_CASH}"

    async def create_lnurl(self, mint_url: Optional[str] = None) -> str:
        """
        Registers the LNURL.
        Raises exception if already registered.
        """
        if not self.npub:
            self._derive_keys()

        # Check if already registered
        try:
            # Check user info. If mintUrl is already set, consider it created.
            data = await self._request("GET", "/user/info")
            user = data.get("user", {})
            if user.get("mintUrl"):
                 raise Exception(f"LNURL already created: {self.npub}@{NPUB_CASH}")
        except Exception as e:
            if "LNURL already created" in str(e):
                raise e
            # Other errors (e.g. 404/401?) mean we probably need to create it.
            # But GET /user/info should create the user if not exists (per code).
            pass

        mint_to_use = mint_url or self.wallet.url
        if not mint_to_use:
             raise ValueError("No mint URL provided or found in wallet")

        # Use PATCH /api/v2/user/mint with mint_url body
        await self._request("PATCH", "/user/mint", body={"mint_url": mint_to_use})
        
        return await self.get_lnurl()

    async def update_mint_url(self, mint_url: Optional[str] = None) -> str:
        """Updates the mint URL for the LNURL."""
        if not self.npub:
            self._derive_keys()
            
        mint_to_use = mint_url or self.wallet.url
        if not mint_to_use:
             raise ValueError("No mint URL provided or found in wallet")

        await self._request("PATCH", "/user/mint", body={"mint_url": mint_to_use})
        return await self.get_lnurl()

    async def check_quotes(self) -> List[Dict]:
        """Fetches all paid quotes from the API."""
        if not self.privkey_hex:
            self._derive_keys()
        
        try:
            data = await self._request("GET", "/wallet/quotes")
            # API v2 returns data object containing 'quotes' list
            quotes = data.get("quotes", [])
            if not quotes:
                return []
            # Filter for paid quotes (state="PAID" or having paidAt)
            return [q for q in quotes if q.get("state") == "PAID" or q.get("paidAt")]
        except Exception as e:
            # If we fail to get quotes (e.g. 401), we assume no quotes or not set up
            print(f"Error checking quotes: {e}")
            return []

    async def mint_quotes(self) -> List[Any]:
        """
        Mints all paid quotes associated with the current wallet's mint.
        Returns a list of minted proofs.
        """
        if not self.wallet.url:
             raise ValueError("Wallet mint URL not set")
             
        quotes = await self.check_quotes()
        minted_proofs = []
        
        for quote_dict in quotes:
            # quote['mintUrl'] contains the mint URL used for this quote
            quote_mint = quote_dict.get("mintUrl") or quote_dict.get("mint")
            if not quote_mint:
                continue

            if quote_mint.rstrip("/") != self.wallet.url.rstrip("/"):
                print(f"Skipping quote {quote_dict.get('id', 'unknown')} from different mint: {quote_mint} (Wallet: {self.wallet.url})")
                continue
            
            quote_id = quote_dict.get("quoteId") or quote_dict.get("id")
            amount = quote_dict.get("amount")
            
            if not quote_id or not amount:
                continue
                
            try:
                # Mint tokens
                # For v2, we are minting the quote ID that NPC created.
                # Check if we have the quote in the database and if it is already issued
                quote = await get_bolt11_mint_quote(db=self.wallet.db, quote=quote_id)
                if quote and quote.state == MintQuoteState.issued:
                    print(f"Quote {quote_id} already minted.")
                    continue

                # Ensure we have the quote in the database
                if not quote:
                    quote = await self.wallet.get_mint_quote(quote_id)
                    if quote.state == MintQuoteState.issued:
                        print(f"Quote {quote_id} already minted.")
                        continue

                proofs = await self.wallet.mint(amount, quote_id=quote_id)
                minted_proofs.extend(proofs)
            except Exception as e:
                print(f"Failed to mint quote {quote_id}: {e}")
                pass
                
        return minted_proofs
