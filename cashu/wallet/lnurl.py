import json
from typing import Optional

import bech32
import httpx


async def get_lnurl_response(url: str) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.get(url, follow_redirects=True)
        r.raise_for_status()
        return r.json()

def decode_lnurl(lnurl: str) -> Optional[str]:
    hrp, data = bech32.bech32_decode(lnurl)
    if not hrp or hrp != "lnurl":
        return None
    if data is None:
        return None
    decoded_data = bech32.convertbits(data, 5, 8, False)
    if decoded_data is None:
        return None
    return bytes(decoded_data).decode("utf-8")

def resolve_lightning_address(address: str) -> Optional[str]:
    parts = address.split("@")
    if len(parts) != 2:
        return None
    user, domain = parts
    return f"https://{domain}/.well-known/lnurlp/{user}"

async def handle_lnurl(lnurl: str, amount: Optional[int]) -> Optional[str]:
    """
    Resolves LNURL or Lightning Address to a bolt11 invoice.
    Returns the bolt11 invoice or None if failed.
    """
    url = None
    if lnurl.lower().startswith("lnurl"):
        url = decode_lnurl(lnurl)
    elif "@" in lnurl:
        url = resolve_lightning_address(lnurl)
    
    if not url:
        return None
        
    try:
        data = await get_lnurl_response(url)
    except Exception as e:
        print(f"Error fetching LNURL: {e}")
        return None
        
    if data.get("tag") != "payRequest":
        print("Error: Invalid LNURL tag. Only payRequest is supported.")
        return None
        
    min_sendable = data.get("minSendable")
    max_sendable = data.get("maxSendable")
    callback = data.get("callback")
    metadata = data.get("metadata")
    
    if not min_sendable or not max_sendable or not callback:
        print("Error: Invalid LNURL response.")
        return None

    if amount:
        amount_msat = amount * 1000
        if amount_msat < min_sendable or amount_msat > max_sendable:
            print(f"Error: Amount {amount} sats is out of range [{int(min_sendable/1000)}, {int(max_sendable/1000)}] sats.")
            return None
    else:
        try:
            if metadata and isinstance(metadata, str):
                meta = json.loads(metadata)
                description = next((item[1] for item in meta if item[0] == 'text/plain'), "")
                if description:
                    print(f"Description: {description}")
        except Exception:
            pass
            
        print(f"Amount range: {int(min_sendable/1000)} - {int(max_sendable/1000)} sats")
        amount_input = input("Enter amount (sats): ")
        try:
            amount = int(amount_input)
            amount_msat = amount * 1000
        except ValueError:
            print("Invalid amount.")
            return None
            
        if amount_msat < min_sendable or amount_msat > max_sendable:
             print(f"Error: Amount {amount} sats is out of range.")
             return None

    separator = "&" if "?" in callback else "?"
    callback_url = f"{callback}{separator}amount={amount_msat}"
    
    try:
        invoice_data = await get_lnurl_response(callback_url)
    except Exception as e:
        print(f"Error fetching invoice: {e}")
        return None
        
    if invoice_data.get("status") == "ERROR":
         print(f"Error from LNURL service: {invoice_data.get('reason')}")
         return None

    pr = invoice_data.get("pr")
    if not pr:
        print("Error: No payment request in response.")
        return None
        
    return pr
