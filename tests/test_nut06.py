import hashlib
from unittest.mock import patch

from cashu.core.nuts.nut06 import (
    canonicalize_mint_info,
    derive_mint_identity_key,
    sign_mint_info,
    verify_mint_info_signature,
)

SEED = b"NUT-06 example mint seed"
INFO = {
    "name": "Bob's Cashu mint",
    "pubkey": "0338596797cef0627f653cd6568387361b00314add55d9f1ea9c94f46ae421e3da",
    "signature": "excluded",
    "version": "Nutshell/0.15.0",
    "description": "The short mint description",
    "description_long": "A description that can be a long piece of text.",
    "contact": [
        {"method": "email", "info": "contact@me.com"},
        {"method": "twitter", "info": "@me"},
        {"method": "nostr", "info": "npub..."},
    ],
    "motd": "Message to display to users.",
    "icon_url": "https://mint.host/icon.jpg",
    "urls": [
        "https://mint.host",
        "http://mint8gv0sq5ul602uxt2fe0t80e3c2bi9fy0cxedp69v1vat6ruj81wv.onion",
    ],
    "time": 1725304480,
    "tos_url": "https://mint.host/tos",
    "nuts": {
        "4": {
            "methods": [
                {
                    "method": "bolt11",
                    "unit": "sat",
                    "min_amount": 0,
                    "max_amount": 10000,
                }
            ],
            "disabled": False,
        },
        "5": {
            "methods": [
                {
                    "method": "bolt11",
                    "unit": "sat",
                    "min_amount": 100,
                    "max_amount": 10000,
                }
            ],
            "disabled": False,
        },
        "7": {"supported": True},
        "8": {"supported": True},
        "9": {"supported": True},
        "10": {"supported": True},
        "12": {"supported": True},
    },
}


def test_mint_identity_derivation_vector():
    key = derive_mint_identity_key(SEED)
    assert key.secret.hex() == (
        "3842a716975d6611d7ae4b36e28068c963e6d8ddb2b70d031d46a79d1df24c3c"
    )
    assert key.public_key.format().hex() == INFO["pubkey"]


def test_mint_identity_derivation_retries_invalid_scalar():
    valid_digest = bytes.fromhex(
        "3842a716975d6611d7ae4b36e28068c963e6d8ddb2b70d031d46a79d1df24c3c"
    )
    digests = iter([bytes(32), valid_digest])

    with patch("cashu.core.nuts.nut06.hmac.digest") as hmac_digest:
        hmac_digest.side_effect = lambda *_args, **_kwargs: next(digests)
        key = derive_mint_identity_key(SEED)

    assert key.secret == valid_digest


def test_mint_info_signature_vector():
    key = derive_mint_identity_key(SEED)
    payload = canonicalize_mint_info(INFO)
    assert hashlib.sha256(payload).hexdigest() == (
        "99eb9a083e7deb7e79c73ee6601690acfbe23766759dd836848cfd49087994ec"
    )
    signature = sign_mint_info(INFO, key, bytes(32))
    assert signature.hex() == (
        "d1ae4c576e3ffa667df795b06655a5400e590653ae1f60f2a256c01e794a7032"
        "8fee6fc8f4139c86458d12c0d4f04781581a5890a9ee83b9f7c72c78a641add0"
    )
    assert verify_mint_info_signature(INFO, signature, key.public_key.format())
