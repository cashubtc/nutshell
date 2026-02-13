import hashlib
import time
import base64
import json
from typing import Optional, Tuple
from coincurve import PrivateKey
from bech32 import bech32_encode, convertbits
from bip32 import BIP32
from cashu.core.settings import settings

def derive_nostr_keypair(seed_bytes: bytes) -> Tuple[str, str]:
    """
    Derives a Nostr keypair (private key, public key) from the wallet seed.
    Uses path m/44'/1237'/0'/0/0 (NIP-06).
    Returns hex-encoded strings.
    """
    bip32 = BIP32.from_seed(seed_bytes)
    # m/44'/1237'/0'/0/0
    child_key = bip32.get_privkey_from_path([44 + 0x80000000, 1237 + 0x80000000, 0 + 0x80000000, 0, 0])
    privkey_hex = child_key.hex()
    
    pk = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = pk.public_key.format(compressed=True)[1:].hex()
    
    return privkey_hex, pubkey_hex

def get_npub(pubkey_hex: str) -> str:
    """Encodes a hex public key to npub format."""
    data = bytes.fromhex(pubkey_hex)
    five_bit_data = convertbits(data, 8, 5)
    return bech32_encode("npub", five_bit_data)

def sign_event(event: dict, privkey_hex: str) -> dict:
    """Signs a Nostr event."""
    pk = PrivateKey(bytes.fromhex(privkey_hex))
    
    serialized_event = json.dumps([
        0,
        event['pubkey'],
        event['created_at'],
        event['kind'],
        event['tags'],
        event['content']
    ], separators=(',', ':'), ensure_ascii=False)
    
    event_id = hashlib.sha256(serialized_event.encode('utf-8')).hexdigest()
    sig = pk.sign_schnorr(bytes.fromhex(event_id), None).hex()
    
    event['id'] = event_id
    event['sig'] = sig
    return event

def create_nip98_header(url: str, method: str, privkey_hex: str, body: Optional[dict] = None) -> str:
    """
    Creates a NIP-98 authorization header.
    """
    pk = PrivateKey(bytes.fromhex(privkey_hex))
    pubkey_hex = pk.public_key.format(compressed=True)[1:].hex()

    event = {
        "kind": 27235,
        "created_at": int(time.time()),
        "tags": [
            ["u", url],
            ["method", method],
        ],
        "content": "",
        "pubkey": pubkey_hex,
    }
    
    if body:
        body_str = json.dumps(body, separators=(',', ':'), ensure_ascii=False)
        body_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()
        event['tags'].append(["payload", body_hash])

    signed_event = sign_event(event, privkey_hex)
    token = base64.b64encode(json.dumps(signed_event).encode('utf-8')).decode('utf-8')
    return f"Nostr {token}"
