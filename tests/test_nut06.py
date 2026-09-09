import hashlib
from unittest.mock import patch

import pytest

from cashu.core.nuts.nut06 import (
    MINT_INFO_TAG_HASH,
    canonicalize_mint_info,
    derive_mint_identity_key,
    mint_info_message_hash,
    sign_mint_info,
    verify_mint_info_signature,
)

SEED = b"NUT-06 example mint seed"
CHALLENGE = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
INFO = {
    "name": "Bob's Cashu mint",
    "pubkey": "0338596797cef0627f653cd6568387361b00314add55d9f1ea9c94f46ae421e3da",
    "signature": "excluded",
    "challenge": CHALLENGE,
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
MINIMAL_INFO = {"pubkey": INFO["pubkey"], "time": INFO["time"]}


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


def test_mint_info_tag_hash_vector():
    assert MINT_INFO_TAG_HASH.hex() == (
        "916a34ebf6f2244d64490e8eb2b5e7af19cdc45aa6176160186fc6543aa20d9b"
    )


@pytest.mark.parametrize(
    "info, expected_hash, expected_signature",
    [
        (
            INFO,
            "3c08960dfc7c5f62e489271ed44cf82240b3fe48a13968179683461444855db6",
            "e91f667871ff922f7430aee729bc0252ff893ec2b05ef2b0f98376f7f5119b152"
            "029b363f89c35ffa2d8e3395c889c5caa2484c8b716cc18881dad7b6ef9a739",
        ),
        (
            {**MINIMAL_INFO, "challenge": CHALLENGE},
            "374353ff76b340d0010379009839f8b29152808ec393409cfb79abf4b19e65bc",
            "e22072aff2d70f9cb210ae5bb9a1d3fe44349cbde03fcd26a73e0c10e30bb3b8"
            "01046db0b096d02f25c8cf76dd24ffd6c1906c3cbc98193c7d2d8d6978c95f0a",
        ),
        (
            MINIMAL_INFO,
            "f50b2ddcbb72c59c25a17019d310ab5e73d2506f508522fa521fbd336aa9159c",
            "1d48ab4a18f5680f9cbc28481c1c9921615cd0fbb8a8f3a015ec47ddf4720b69"
            "f7e870d8195c65b30445ce35b0d3035819ccc3adbea741873cf1e44cb9a48998",
        ),
    ],
    ids=["full", "minimal-with-challenge", "minimal-without-challenge"],
)
def test_mint_info_signature_vector(info, expected_hash, expected_signature):
    key = derive_mint_identity_key(SEED)
    assert mint_info_message_hash(info).hex() == expected_hash
    signature = sign_mint_info(info, key, bytes(32))
    assert signature.hex() == expected_signature
    assert verify_mint_info_signature(
        info,
        signature,
        key.public_key.format(),
        verifier_time=INFO["time"],
        expected_challenge=info.get("challenge"),
    )


@pytest.mark.parametrize(
    "info", [INFO, {**MINIMAL_INFO, "challenge": CHALLENGE}, MINIMAL_INFO]
)
def test_mint_info_signature_rejects_untagged_hash(info):
    key = derive_mint_identity_key(SEED)
    signature = key.sign_schnorr(
        hashlib.sha256(canonicalize_mint_info(info)).digest(), bytes(32)
    )
    assert not verify_mint_info_signature(
        info, signature, key.public_key.format(), verifier_time=INFO["time"]
    )


def test_mint_info_signature_ignores_member_order_and_signature_field():
    key = derive_mint_identity_key(SEED)
    signature = sign_mint_info(INFO, key, bytes(32))
    reordered = dict(reversed(list(INFO.items())))
    reordered["signature"] = signature.hex()
    assert verify_mint_info_signature(
        reordered,
        signature,
        key.public_key.format(),
        verifier_time=INFO["time"],
        expected_challenge=CHALLENGE,
    )


@pytest.mark.parametrize("challenge", [None, "", "00" * 32, CHALLENGE.upper(), 0])
def test_mint_info_signature_rejects_missing_malformed_or_mismatched_challenge(
    challenge,
):
    key = derive_mint_identity_key(SEED)
    info = {**INFO, "challenge": challenge}
    if challenge is None:
        del info["challenge"]
    # Sign the changed payload to check challenge binding independently of the signature.
    signature = sign_mint_info(info, key, bytes(32))
    assert not verify_mint_info_signature(
        info,
        signature,
        key.public_key.format(),
        verifier_time=INFO["time"],
        expected_challenge=CHALLENGE,
    )


@pytest.mark.parametrize(
    "change",
    [{"challenge": "00" * 32}, {"time": 1725304481}, {"name": "Another mint"}],
)
def test_mint_info_signature_rejects_tampered_payload(change):
    key = derive_mint_identity_key(SEED)
    signature = sign_mint_info(INFO, key, bytes(32))
    info = {**INFO, **change}
    assert not verify_mint_info_signature(
        info,
        signature,
        key.public_key.format(),
        verifier_time=INFO["time"],
        expected_challenge=info["challenge"],
    )


def test_mint_info_signature_enforces_time_window():
    key = derive_mint_identity_key(SEED)
    signature = sign_mint_info(INFO, key, bytes(32))
    pubkey = key.public_key.format()

    assert verify_mint_info_signature(
        INFO, signature, pubkey, verifier_time=INFO["time"] - 3600
    )
    assert verify_mint_info_signature(
        INFO, signature, pubkey, verifier_time=INFO["time"] + 3600
    )
    assert not verify_mint_info_signature(
        INFO, signature, pubkey, verifier_time=INFO["time"] - 3601
    )
    assert not verify_mint_info_signature(
        INFO, signature, pubkey, verifier_time=INFO["time"] + 3601
    )


def test_mint_info_signature_rejects_missing_or_malformed_time():
    key = derive_mint_identity_key(SEED)
    pubkey = key.public_key.format()

    for invalid_time in (None, 1725304480.0, "1725304480", True):
        info = {**INFO, "time": invalid_time}
        signature = sign_mint_info(info, key, bytes(32))
        assert not verify_mint_info_signature(
            info, signature, pubkey, verifier_time=INFO["time"]
        )
