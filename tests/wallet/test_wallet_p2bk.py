"""Tests for NUT-28: Pay-to-Blinded-Key (P2BK)"""

import copy
import secrets
from typing import List

import pytest
import pytest_asyncio

from cashu.core.base import BlindedMessage, Proof
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.migrations import migrate_databases
from cashu.core.p2bk import (
    SECP256K1_ORDER,
    _compressed_pubkey,
    _pubkey_x,
    blind_pubkeys,
    derive_blinded_private_key,
    derive_blinding_scalar,
    ecdh_shared_secret,
)
from cashu.core.p2pk import P2PKSecret, SigFlags, schnorr_sign
from cashu.core.secret import Secret, SecretKind
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet
from tests.conftest import SERVER_ENDPOINT
from tests.helpers import pay_if_regtest


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        exc_msg = str(exc)
        if msg and msg not in exc_msg:
            raise Exception(f"Expected error: {msg}, got: {exc_msg}")
        return
    raise Exception(f"Expected error: {msg}, got no error")


@pytest_asyncio.fixture(scope="function")
async def wallet1():
    wallet1 = await Wallet.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2bk_1", "wallet1"
    )
    await migrate_databases(wallet1.db, migrations)
    await wallet1.load_mint()
    yield wallet1


@pytest_asyncio.fixture(scope="function")
async def wallet2():
    wallet2 = await Wallet.with_db(
        SERVER_ENDPOINT, "test_data/wallet_p2bk_2", "wallet2"
    )
    await migrate_databases(wallet2.db, migrations)
    wallet2.private_key = PrivateKey(secrets.token_bytes(32))
    await wallet2.load_mint()
    yield wallet2


# ──────────────────────────────────────────────
# Unit tests for core P2BK primitives
# ──────────────────────────────────────────────


def test_compressed_pubkey_32_bytes():
    """x-only (32 byte) key gets an 02 prefix."""
    priv = PrivateKey()
    assert priv.public_key
    x_only = priv.public_key.format(compressed=True)[1:].hex()
    assert len(bytes.fromhex(x_only)) == 32
    result = _compressed_pubkey(x_only)
    assert result.startswith("02")
    assert len(bytes.fromhex(result)) == 33


def test_compressed_pubkey_33_bytes():
    """Already compressed key passes through."""
    priv = PrivateKey()
    assert priv.public_key
    compressed = priv.public_key.format(compressed=True).hex()
    assert _compressed_pubkey(compressed) == compressed


def test_compressed_pubkey_invalid():
    """Invalid length raises ValueError."""
    with pytest.raises(ValueError):
        _compressed_pubkey("aabbccdd")  # 4 bytes


def test_ecdh_shared_secret_commutative():
    """Zx = x(e*P) == x(p*E)."""
    e = PrivateKey()
    p = PrivateKey()
    assert e.public_key and p.public_key
    E = e.public_key
    P = p.public_key
    zx_sender = ecdh_shared_secret(P, e)  # sender computes e*P
    zx_receiver = ecdh_shared_secret(E, p)  # receiver computes p*E
    assert zx_sender == zx_receiver
    assert len(zx_sender) == 32


def test_derive_blinding_scalar_deterministic():
    """Same inputs always produce the same scalar."""
    zx = secrets.token_bytes(32)
    r1 = derive_blinding_scalar(zx, 0)
    r2 = derive_blinding_scalar(zx, 0)
    assert r1 == r2


def test_derive_blinding_scalar_different_slots():
    """Different slot indices produce different scalars."""
    zx = secrets.token_bytes(32)
    r0 = derive_blinding_scalar(zx, 0)
    r1 = derive_blinding_scalar(zx, 1)
    assert r0 != r1


def test_derive_blinding_scalar_range():
    """Scalar must be 1 <= r < n."""
    zx = secrets.token_bytes(32)
    for i in range(11):  # slots 0-10
        r = derive_blinding_scalar(zx, i)
        assert 1 <= r < SECP256K1_ORDER


def test_blind_pubkeys_roundtrip():
    """Blinded keys can be unblinded by the receiver."""
    receiver_priv = PrivateKey()
    assert receiver_priv.public_key
    receiver_pub_hex = receiver_priv.public_key.format(compressed=True).hex()

    blinded_data, blinded_add, blinded_refund, ephemeral_pub = blind_pubkeys(
        data_pubkey=receiver_pub_hex,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=receiver_pub_hex,
    )

    # Receiver should be able to derive the private key for slot 0
    derived_key = derive_blinded_private_key(
        privkey=receiver_priv,
        ephemeral_pubkey_hex=ephemeral_pub,
        blinded_pubkey_hex=blinded_data,
        slot_index=0,
    )
    assert derived_key is not None
    # The derived key's public key should match the blinded pubkey
    assert derived_key.public_key
    # The x-coordinates must match (BIP-340 schnorr uses x-only)
    assert _pubkey_x(derived_key.public_key) == _pubkey_x(
        PublicKey(bytes.fromhex(_compressed_pubkey(blinded_data)))
    )


def test_blind_pubkeys_with_additional_and_refund():
    """Blinding works with multiple pubkeys in different slots."""
    receiver_priv = PrivateKey()
    assert receiver_priv.public_key
    receiver_pub = receiver_priv.public_key.format(compressed=True).hex()

    # Additional pubkey (same receiver for simplicity)
    add_pub = receiver_pub
    refund_pub = receiver_pub

    blinded_data, blinded_add, blinded_refund, E = blind_pubkeys(
        data_pubkey=receiver_pub,
        additional_pubkeys=[add_pub],
        refund_pubkeys=[refund_pub],
        receiver_pubkey=receiver_pub,
    )

    assert len(blinded_add) == 1
    assert len(blinded_refund) == 1

    # All three slots should produce valid derived keys
    for slot_idx, blinded_pk in enumerate(
        [blinded_data] + blinded_add + blinded_refund
    ):
        derived = derive_blinded_private_key(
            privkey=receiver_priv,
            ephemeral_pubkey_hex=E,
            blinded_pubkey_hex=blinded_pk,
            slot_index=slot_idx,
        )
        assert derived is not None, f"Failed to derive key for slot {slot_idx}"


def test_wrong_receiver_cannot_unblind():
    """A different private key cannot unblind."""
    receiver_priv = PrivateKey()
    wrong_priv = PrivateKey()
    assert receiver_priv.public_key
    receiver_pub = receiver_priv.public_key.format(compressed=True).hex()

    blinded_data, _, _, E = blind_pubkeys(
        data_pubkey=receiver_pub,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=receiver_pub,
    )

    derived = derive_blinded_private_key(
        privkey=wrong_priv,
        ephemeral_pubkey_hex=E,
        blinded_pubkey_hex=blinded_data,
        slot_index=0,
    )
    assert derived is None


def test_blinded_pubkey_differs_from_original():
    """Blinded pubkey P' != original pubkey P."""
    priv = PrivateKey()
    assert priv.public_key
    pub = priv.public_key.format(compressed=True).hex()

    blinded_data, _, _, _ = blind_pubkeys(
        data_pubkey=pub,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=pub,
    )
    assert blinded_data.lower() != pub.lower()


def test_different_ephemeral_keys_produce_different_blinding():
    """Each fresh ephemeral key produces unique blinding."""
    priv = PrivateKey()
    assert priv.public_key
    pub = priv.public_key.format(compressed=True).hex()

    blinded1, _, _, E1 = blind_pubkeys(
        data_pubkey=pub,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=pub,
    )
    blinded2, _, _, E2 = blind_pubkeys(
        data_pubkey=pub,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=pub,
    )
    assert E1 != E2  # random ephemeral keys
    assert blinded1 != blinded2  # different blinding


def test_derived_key_can_sign_and_verify():
    """Derived blinded private key can produce valid schnorr signatures."""
    receiver_priv = PrivateKey()
    assert receiver_priv.public_key
    receiver_pub = receiver_priv.public_key.format(compressed=True).hex()

    blinded_data, _, _, E = blind_pubkeys(
        data_pubkey=receiver_pub,
        additional_pubkeys=[],
        refund_pubkeys=[],
        receiver_pubkey=receiver_pub,
    )

    derived_key = derive_blinded_private_key(
        privkey=receiver_priv,
        ephemeral_pubkey_hex=E,
        blinded_pubkey_hex=blinded_data,
        slot_index=0,
    )
    assert derived_key is not None

    # Sign a message
    message = b"test message"
    sig = schnorr_sign(message, derived_key)

    # Verify against the blinded pubkey
    from cashu.core.p2pk import verify_schnorr_signature

    blinded_pk = PublicKey(bytes.fromhex(_compressed_pubkey(blinded_data)))
    assert verify_schnorr_signature(message, blinded_pk, sig)


def test_compressed_pubkey_x_only_nostr():
    """Simulating a Nostr-style 32-byte hex key getting 02 prefix."""
    # Use a real private key to derive an x-only pubkey (like Nostr npub)
    priv = PrivateKey(secrets.token_bytes(32))
    x_only_hex = priv.public_key.format(compressed=True).hex()[2:]  # strip 02/03
    assert len(x_only_hex) == 64
    result = _compressed_pubkey(x_only_hex)
    assert result.startswith("02")
    # Verify it's a valid point
    PublicKey(bytes.fromhex(result))


# ──────────────────────────────────────────────
# Integration tests: P2BK with wallet + mint
# ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_p2bk_basic(wallet1: Wallet, wallet2: Wallet):
    """Basic P2BK: sender blinds, receiver unblinds and redeems."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()

    # Sender creates a P2BK lock
    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(pubkey_wallet2)

    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    # Verify proofs have p2pk_e
    for p in send_proofs:
        assert p.p2pk_e == ephemeral_pub

    # Verify the secret contains blinded pubkeys (not the original)
    for p in send_proofs:
        secret = P2PKSecret.deserialize(p.secret)
        assert secret.data.lower() != pubkey_wallet2.lower()

    # Receiver redeems (the wallet should unblind via p2pk_e)
    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2bk_wrong_receiver(wallet1: Wallet, wallet2: Wallet):
    """P2BK: wrong private key cannot redeem."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()

    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    # Set wrong private key on wallet2
    wallet2.private_key = PrivateKey()
    await assert_err(wallet2.redeem(send_proofs), "")


@pytest.mark.asyncio
async def test_p2bk_sig_all(wallet1: Wallet, wallet2: Wallet):
    """P2BK with SIG_ALL spending condition."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()

    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(
        pubkey_wallet2, sig_all=True
    )
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    # Verify SIG_ALL flag
    for p in send_proofs:
        secret = P2PKSecret.deserialize(p.secret)
        p2pk = P2PKSecret.from_secret(secret)
        assert p2pk.sigflag == SigFlags.SIG_ALL

    # All SIG_ALL proofs must carry the *same* ephemeral key
    e_values = [p.p2pk_e for p in send_proofs]
    assert all(e == ephemeral_pub for e in e_values), (
        f"Expected identical p2pk_e across SIG_ALL proofs, got {e_values}"
    )

    await wallet2.redeem(send_proofs)


@pytest.mark.asyncio
async def test_p2bk_mint_sees_normal_p2pk(wallet1: Wallet, wallet2: Wallet):
    """The mint sees a standard P2PK secret, not P2BK metadata."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()

    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    # The secret kind is still P2PK
    for p in send_proofs:
        secret = Secret.deserialize(p.secret)
        assert secret.kind == SecretKind.P2PK.value

    # p2pk_e is stripped during signing/sending to mint
    # (sign_proofs_inplace_swap strips it)
    proofs_copy = copy.deepcopy(send_proofs)
    outputs = await _create_outputs(wallet2, 8)
    signed = wallet2.sign_proofs_inplace_swap(proofs_copy, outputs)
    for p in signed:
        assert p.p2pk_e is None


@pytest.mark.asyncio
async def test_p2bk_unique_ephemeral_per_output(wallet1: Wallet, wallet2: Wallet):
    """Each output gets a unique ephemeral keypair when not SIG_ALL."""
    mint_quote = await wallet1.request_mint(128)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(128, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()

    # Create two separate P2BK locks (each gets a fresh E)
    lock1, E1 = await wallet1.create_p2bk_lock(pubkey_wallet2)
    lock2, E2 = await wallet1.create_p2bk_lock(pubkey_wallet2)
    assert E1 != E2  # unique ephemeral keys


@pytest.mark.asyncio
async def test_p2bk_token_v4_roundtrip(wallet1: Wallet, wallet2: Wallet):
    """P2BK proofs survive Token V4 (CBOR) serialize/deserialize."""
    from cashu.core.base import TokenV4

    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    # Serialize as Token V4
    token_str = await wallet1.serialize_proofs(send_proofs)
    assert token_str.startswith("cashuB") or token_str.startswith("cashuA")

    # Deserialize
    if token_str.startswith("cashuB"):
        token = TokenV4.deserialize(token_str)
        deserialized_proofs = token.proofs
    else:
        from cashu.core.base import TokenV3

        token_v3 = TokenV3.deserialize(token_str)
        deserialized_proofs = token_v3.proofs

    # p2pk_e should survive roundtrip
    for p in deserialized_proofs:
        assert p.p2pk_e == ephemeral_pub


@pytest.mark.asyncio
async def test_p2bk_proof_dict_roundtrip(wallet1: Wallet, wallet2: Wallet):
    """p2pk_e survives Proof.to_dict / Proof.from_dict roundtrip."""
    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock, ephemeral_pub = await wallet1.create_p2bk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock, p2pk_e=ephemeral_pub
    )

    for p in send_proofs:
        d = p.to_dict()
        assert "p2pk_e" in d
        assert d["p2pk_e"] == ephemeral_pub
        restored = Proof.from_dict(d)
        assert restored.p2pk_e == ephemeral_pub


@pytest.mark.asyncio
async def test_v4_roundtrip_without_pe(wallet1: Wallet, wallet2: Wallet):
    """A non-P2BK V4 token must roundtrip cleanly with pe absent."""
    from cashu.core.base import TokenV4

    mint_quote = await wallet1.request_mint(64)
    await pay_if_regtest(mint_quote.request)
    await wallet1.mint(64, quote_id=mint_quote.quote)

    # Plain P2PK (no P2BK), so no pe field
    pubkey_wallet2 = await wallet2.create_p2pk_pubkey()
    secret_lock = await wallet1.create_p2pk_lock(pubkey_wallet2)
    _, send_proofs = await wallet1.swap_to_send(
        wallet1.proofs, 8, secret_lock=secret_lock
    )

    # Sanity: no p2pk_e on plain P2PK proofs
    for p in send_proofs:
        assert p.p2pk_e is None

    # Serialize → deserialize as V4
    token_str = await wallet1.serialize_proofs(send_proofs)
    if token_str.startswith("cashuB"):
        token = TokenV4.deserialize(token_str)
        deserialized_proofs = token.proofs
    else:
        from cashu.core.base import TokenV3
        token_v3 = TokenV3.deserialize(token_str)
        deserialized_proofs = token_v3.proofs

    # pe must remain absent — not an empty string, not zero-bytes
    for p in deserialized_proofs:
        assert p.p2pk_e is None


async def _create_outputs(wallet: Wallet, amount: int) -> List[BlindedMessage]:
    """Helper to create blinded outputs."""
    output_amounts = [amount]
    secrets, rs, _ = await wallet.generate_n_secrets(len(output_amounts))
    outputs, _ = wallet._construct_outputs(output_amounts, secrets, rs)
    return outputs
