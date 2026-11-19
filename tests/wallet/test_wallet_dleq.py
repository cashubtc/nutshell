import pytest

from cashu.core.base import DLEQWallet, Proof, WalletKeyset
from cashu.core.crypto import b_dhke
from cashu.core.crypto.secp import PrivateKey
from cashu.wallet.wallet import Wallet


@pytest.fixture
def wallet_and_proofs(tmp_path):
    mint_key = PrivateKey(bytes.fromhex("01" * 32))
    keyset = WalletKeyset(public_keys={1: mint_key.public_key}, unit="sat")
    wallet = Wallet(url="https://mint.test", db=str(tmp_path))
    wallet.keysets = {keyset.id: keyset}

    proofs = {}
    for kind in ("valid", "missing", "invalid"):
        secret = f"test-dleq-{kind}"
        B_, r = b_dhke.step1_alice(secret, PrivateKey(bytes.fromhex("02" * 32)))
        C_, e, s = b_dhke.step2_bob(B_, mint_key)
        C = b_dhke.step3_alice(C_, r, mint_key.public_key)
        proof = Proof(
            id=keyset.id,
            amount=1,
            secret=secret,
            C=C.format().hex(),
            dleq=DLEQWallet(e=e.to_hex(), s=s.to_hex(), r=r.to_hex()),
        )
        if kind == "missing":
            proof.dleq = None
        elif kind == "invalid":
            proof.dleq = DLEQWallet(e="11" * 32, s="22" * 32, r="33" * 32)
        proofs[kind] = proof

    return wallet, proofs


@pytest.mark.parametrize(
    "order",
    [
        ("invalid",),
        ("invalid", "missing", "valid"),
        ("valid", "invalid", "missing"),
        ("missing", "invalid", "missing"),
        ("valid", "missing", "invalid"),
        ("missing", "valid", "invalid"),
        ("missing", "missing", "invalid"),
    ],
    ids=lambda order: "-".join(order),
)
def test_verify_proofs_dleq_rejects_invalid_regardless_of_order(
    wallet_and_proofs, order
):
    wallet, proofs = wallet_and_proofs

    with pytest.raises(Exception, match="^DLEQ proof invalid\\.$"):
        wallet.verify_proofs_dleq([proofs[kind] for kind in order])


@pytest.mark.parametrize(
    "order",
    [
        (),
        ("missing",),
        ("missing", "missing"),
        ("valid",),
        ("valid", "missing"),
        ("missing", "valid"),
        ("missing", "valid", "missing", "valid"),
    ],
    ids=lambda order: "-".join(order) or "empty",
)
def test_verify_proofs_dleq_accepts_valid_and_missing_dleqs(wallet_and_proofs, order):
    wallet, proofs = wallet_and_proofs

    wallet.verify_proofs_dleq([proofs[kind] for kind in order])
