import hashlib
import json

import pytest

from cashu.core.base import Proof, TokenV4
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.p2bk import (
    blind_pubkeys,
    derive_blinded_private_key,
    derive_blinding_scalar,
    ecdh_shared_secret,
)
from cashu.core.p2pk import P2PKSecret
from cashu.core.secret import SecretKind
from cashu.wallet.p2bk import WalletP2BK


@pytest.fixture(autouse=True, scope="session")
def mint():
    # Override autouse server fixture from tests/conftest.py to avoid hanging
    yield


# --- Vector inputs (28-tests.md) ---

E_PRIVKEY_HEX = "1cedb9df0c6872188b560ace9e35fd55c2532d53e19ae65b46159073886482ca"
E_PUBKEY_HEX = "02a8cda4cf448bfce9a9e46e588c06ea1780fcb94e3bbdf3277f42995d403a8b0c"
P_PRIVKEY_HEX = "ad37e8abd800be3e8272b14045873f4353327eedeb702b72ddcc5c5adff5129c"
P_PUBKEY_HEX = "02771fed6cb88aaac38b8b32104a942bf4b8f4696bc361171b3c7d06fa2ebddf06"

ZX_HEX = "40d6ba4430a6dfa915bb441579b0f4dee032307434e9957a092bbca73151df8b"

R_HEX = [
    "f43cfecf4d44e109872ed601156a01211c0d9eba0460d5be254a510782a2d4aa",
    "4a57e6acb9db19344af5632aa45000cd2c643550bc63c7d5732221171ab0f5b3",
    "d4a8b84b21f2b0ad31654e96eddbc32bfdedae2d05dc179bdd6cc20236b1104d",
    "ecebf43123d1da3de611a05f5020085d63ca20829242cdc07f7c780e19594798",
    "5f42d463ead44cbb20e51843d9eb3b8b0e0021566fd89852d23ae85f57d60858",
    "a8f1c9d336954997ad571e5a5b59fe340c80902b10b9099d44e17abb3070118c",
    "c39fa43b707215c163593fb8cadc0eddb4fe2f82c0c79c82a6fc2e3b6b051a7e",
    "b17d6a51396eb926f4a901e20ff760a852563f90fd4b85e193888f34fd2ee523",
    "4d4af85ea296457155b7ce328cf9accbe232e8ac23a1dfe901a36ab1b72ea04d",
    "ce311248ea9f42a73fc874b3ce351d55964652840d695382f0018b36bb089dd1",
    "9de35112d62e6343d02301d8f58fef87958e99bb68cfdfa855e04fe18b95b114",
]

BLINDED_PUBKEY_HEX = [
    "03b7c03eb05a0a539cfc438e81bcf38b65b7bb8685e8790f9b853bfe3d77ad5315",
    "0352fb6d93360b7c2538eedf3c861f32ea5883fceec9f3e573d9d84377420da838",
    "03667361ca925065dcafea0a705ba49e75bdd7975751fcc933e05953463c79fff1",
    "02aca3ed09382151250b38c85087ae0a1436a057b40f824a5569ba353d40347d08",
    "02cd397bd6e326677128f1b0e5f1d745ad89b933b1b8671e947592778c9fc2301d",
    "0394140369aae01dbaf74977ccbb09b3a9cf2252c274c791ac734a331716f1f7d4",
    "03480f28e8f8775d56a4254c7e0dfdd5a6ecd6318c757fcec9e84c1b48ada0666d",
    "02f8a7be813f7ba2253d09705cc68c703a9fd785a055bf8766057fc6695ec80efc",
    "03aa5446aaf07ca9730b233f5c404fd024ef92e3787cd1c34c81c0778fe23c59e9",
    "037f82d4e0a79b0624a58ef7181344b95afad8acf4275dad49bcd39c189b73ece2",
    "032371fc0eef6885062581a3852494e2eab8f384b7dd196281b85b77f94770fac5",
]

# skNeg: negated derivation, (-p + r_i) mod n. The vectors' P has parity
# mismatched against the natural pubkey pG, so this is the branch a
# spec-correct receiver must select (see "Choosing Correct Secret Key
# Derivation" in 28-tests.md).
DERIVED_PRIVKEY_HEX = [
    "47051623754422cb04bc24c0cfe2c1ddc8db1fcc18f0aa4b477df4aca2adc20e",
    "9d1ffe00e1da5af5c882b1ea5ec8c18893e09349803c3c9e552823490af22458",
    "2770cf9f49f1f26eaef29d56a85483e8aabb2f3f1a6bec28ffa065a756bbfdb1",
    "3fb40b854bd11bff639eef1f0a98c91a1097a194a6d2a24da1b01bb3396434fc",
    "b20aebb812d38e7c9e7267039463fc46757c7f4f33b10d1bb440ea91481736fd",
    "fbb9e1275e948b592ae46d1a15d2beef73fcee23d4917e6626e77ced20b14031",
    "1667bb8f98715782e0e68e788554cf9a61cbb094d557710fc92fd1e08b1007e2",
    "044581a5616dfae8723650a1ca702164ff23c0a311db5a6eb5bc32da1d39d287",
    "a0130fb2ca958732d3451cf247726d8749af46a4e77a54b1e3a96ce3a76fcef2",
    "20f9299d129e8468bd55c37388adde124313d39621f9281012352edbdb138b35",
    "f0ab6866fe2da5054db05098b008b042fd0af7b42ca8547137e652137bd6dfb9",
]

EXAMPLE_PROOF = {
    "amount": 64,
    "C": "0381855ddcc434a9a90b3564f29ef78e7271f8544d0056763b418b00e88525c0ff",
    "id": "009a1f293253e41e",
    "secret": '["P2PK",{"nonce":"d4a17a88f5d0c09001f7b453c42c1f9d5a87363b1f6637a5a83fc31a6a3b7266","data":"03b7c03eb05a0a539cfc438e81bcf38b65b7bb8685e8790f9b853bfe3d77ad5315","tags":[]}]',
    "dleq": {
        "s": "6178978456c42eee8eefb50830fc3146be27b05619f04e3490dc596005f0cc78",
        "e": "23f2190b18bfd043d3a526103e15f4a938d646a6bf93b017e2bb7c85e1540b32",
        "r": "d26a55aa39ca50957fdaf54036b01053b0de42048b96a6fb2a167e03f00d0a0f",
    },
    "p2pk_e": "02a8cda4cf448bfce9a9e46e588c06ea1780fcb94e3bbdf3277f42995d403a8b0c",
}

SLOTS = list(range(11))  # 0x00-0x0A


def test_shared_secret_zx_from_sender_side():
    e = PrivateKey(bytes.fromhex(E_PRIVKEY_HEX))
    P = PublicKey(bytes.fromhex(P_PUBKEY_HEX))
    assert ecdh_shared_secret(P, e).hex() == ZX_HEX


def test_shared_secret_zx_from_receiver_side():
    p = PrivateKey(bytes.fromhex(P_PRIVKEY_HEX))
    E = PublicKey(bytes.fromhex(E_PUBKEY_HEX))
    assert ecdh_shared_secret(E, p).hex() == ZX_HEX


@pytest.mark.parametrize("slot", SLOTS)
def test_blinding_scalar_per_slot(slot):
    zx = bytes.fromhex(ZX_HEX)
    r = derive_blinding_scalar(zx, slot)
    assert format(r, "064x") == R_HEX[slot]


def test_blinded_pubkeys_all_slots():
    # NUT-28 slots are positional over [data, ...pubkeys, ...refund]; the
    # vectors blind the *same* receiver pubkey P at every slot 0-10, so
    # exercise blind_pubkeys() exactly as a sender would with 11 locking
    # entries for the same key (cts's lead: extend to all defined slots).
    e = PrivateKey(bytes.fromhex(E_PRIVKEY_HEX))
    blinded_data, blinded_additional, blinded_refund, ephemeral_pubkey_hex = (
        blind_pubkeys(
            data_pubkey=P_PUBKEY_HEX,
            additional_pubkeys=[P_PUBKEY_HEX] * 9,
            refund_pubkeys=[P_PUBKEY_HEX],
            ephemeral_privkey=e,
        )
    )
    assert ephemeral_pubkey_hex == E_PUBKEY_HEX
    all_blinded = [blinded_data] + blinded_additional + blinded_refund
    assert all_blinded == BLINDED_PUBKEY_HEX


@pytest.mark.parametrize("slot", SLOTS)
def test_derived_secret_key_per_slot(slot):
    p = PrivateKey(bytes.fromhex(P_PRIVKEY_HEX))
    derived = derive_blinded_private_key(
        privkey=p,
        ephemeral_pubkey_hex=E_PUBKEY_HEX,
        blinded_pubkey_hex=BLINDED_PUBKEY_HEX[slot],
        slot_index=slot,
    )
    assert derived is not None
    assert derived.to_hex() == DERIVED_PRIVKEY_HEX[slot]


def test_example_proof_slot_0_round_trips():
    proof = Proof(
        amount=EXAMPLE_PROOF["amount"],
        C=EXAMPLE_PROOF["C"],
        id=EXAMPLE_PROOF["id"],
        secret=EXAMPLE_PROOF["secret"],
        p2pk_e=EXAMPLE_PROOF["p2pk_e"],
    )
    secret_data = json.loads(proof.secret)[1]["data"]
    assert secret_data == BLINDED_PUBKEY_HEX[0]
    assert proof.p2pk_e == E_PUBKEY_HEX

    p = PrivateKey(bytes.fromhex(P_PRIVKEY_HEX))
    derived = derive_blinded_private_key(
        privkey=p,
        ephemeral_pubkey_hex=proof.p2pk_e,
        blinded_pubkey_hex=secret_data,
        slot_index=0,
    )
    assert derived is not None
    assert derived.to_hex() == DERIVED_PRIVKEY_HEX[0]


@pytest.mark.parametrize("slot", [-1, 256])
def test_blinding_scalar_refuses_slot_outside_one_byte(slot):
    with pytest.raises(ValueError, match="slot index"):
        derive_blinding_scalar(bytes(32), slot)


# --- HTLC example proof (cashubtc/nuts#402) ---

# The NUT-14 preimage pair reused as the hash lock.
EXAMPLE_HTLC_PREIMAGE_HEX = "00" * 31 + "01"

EXAMPLE_HTLC_PROOF = {
    "amount": 64,
    "C": "0270aba098c920adafa1ce75acefb06d8cc541ef80270f70cc7b66375b789ed9be",
    "id": "009a1f293253e41e",
    "secret": '["HTLC",{"nonce":"8b1f18aa85a2787903cfdc776fde0b8555bdb126eea02b05cd84de06a4f4b551","data":"ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5","tags":[["pubkeys","0352fb6d93360b7c2538eedf3c861f32ea5883fceec9f3e573d9d84377420da838"],["locktime","1689418329"],["refund","03667361ca925065dcafea0a705ba49e75bdd7975751fcc933e05953463c79fff1"]]}]',
    "dleq": {
        "s": "bd6ed079b954151898cadac38c3b8d3371c20d67e8c5f06af3cee4152ac317b4",
        "e": "9ec5b6f2095a8dc7d052a00e0bb050ac95e633e702575630cfd43cb58592d2a1",
        "r": "e8349cf88e5a9f025f0072bf8a2db48d394bad9f7be3d8023f9ee90de1c1924d",
    },
    "p2pk_e": "02a8cda4cf448bfce9a9e46e588c06ea1780fcb94e3bbdf3277f42995d403a8b0c",
}

# The two example proofs encoded as a V4 token, pinning the `pe` field
# (ephemeral pubkey E as a 33-byte CBOR bstr) and the dleq wire format.
EXAMPLE_V4_TOKEN = "cashuBo2FtdWh0dHA6Ly9sb2NhbGhvc3Q6MzMzOGF1Y3NhdGF0gaJhaUgAmh8pMlPkHmFwgqVhYRhAYXN4q1siUDJQSyIseyJub25jZSI6ImQ0YTE3YTg4ZjVkMGMwOTAwMWY3YjQ1M2M0MmMxZjlkNWE4NzM2M2IxZjY2MzdhNWE4M2ZjMzFhNmEzYjcyNjYiLCJkYXRhIjoiMDNiN2MwM2ViMDVhMGE1MzljZmM0MzhlODFiY2YzOGI2NWI3YmI4Njg1ZTg3OTBmOWI4NTNiZmUzZDc3YWQ1MzE1IiwidGFncyI6W119XWFjWCEDgYVd3MQ0qakLNWTynveOcnH4VE0AVnY7QYsA6IUlwP9hZKNhZVggI_IZCxi_0EPTpSYQPhX0qTjWRqa_k7AX4rt8heFUCzJhc1ggYXiXhFbELu6O77UIMPwxRr4nsFYZ8E40kNxZYAXwzHhhclgg0mpVqjnKUJV_2vVANrAQU7DeQgSLlqb7KhZ-A_ANCg9icGVYIQKozaTPRIv86ankbliMBuoXgPy5Tju98yd_QpldQDqLDKVhYRhAYXN5AWNbIkhUTEMiLHsibm9uY2UiOiI4YjFmMThhYTg1YTI3ODc5MDNjZmRjNzc2ZmRlMGI4NTU1YmRiMTI2ZWVhMDJiMDVjZDg0ZGUwNmE0ZjRiNTUxIiwiZGF0YSI6ImVjNDkxNmRkMjhmYzRjMTBkNzhlMjg3Y2E1ZDljYzUxZWUxYWU3M2NiZmRlMDhjNmIzNzMyNGNiZmFhYzhiYzUiLCJ0YWdzIjpbWyJwdWJrZXlzIiwiMDM1MmZiNmQ5MzM2MGI3YzI1MzhlZWRmM2M4NjFmMzJlYTU4ODNmY2VlYzlmM2U1NzNkOWQ4NDM3NzQyMGRhODM4Il0sWyJsb2NrdGltZSIsIjE2ODk0MTgzMjkiXSxbInJlZnVuZCIsIjAzNjY3MzYxY2E5MjUwNjVkY2FmZWEwYTcwNWJhNDllNzViZGQ3OTc1NzUxZmNjOTMzZTA1OTUzNDYzYzc5ZmZmMSJdXX1dYWNYIQJwq6CYySCtr6HOdazvsG2MxUHvgCcPcMx7ZjdbeJ7ZvmFko2FlWCCexbbyCVqNx9BSoA4LsFCsleYz5wJXVjDP1Dy1hZLSoWFzWCC9btB5uVQVGJjK2sOMO40zccINZ-jF8GrzzuQVKsMXtGFyWCDoNJz4jlqfAl8Acr-KLbSNOUutn3vj2AI_nukN4cGSTWJwZVghAqjNpM9Ei_zpqeRuWIwG6heA_LlOO73zJ39CmV1AOosM"


def _assert_proof_matches_example(proof: Proof, example: dict) -> None:
    assert proof.amount == example["amount"]
    assert proof.id == example["id"]
    assert proof.secret == example["secret"]
    assert proof.C == example["C"]
    assert proof.dleq is not None
    assert proof.dleq.e == example["dleq"]["e"]
    assert proof.dleq.s == example["dleq"]["s"]
    assert proof.dleq.r == example["dleq"]["r"]
    assert proof.p2pk_e == example["p2pk_e"]


def test_htlc_example_proof_hash_lock_is_nut14_preimage_pair():
    """Slot 0 holds the hash lock, unblinded: the NUT-14 preimage pair."""
    secret = P2PKSecret.deserialize(EXAMPLE_HTLC_PROOF["secret"])
    preimage = bytes.fromhex(EXAMPLE_HTLC_PREIMAGE_HEX)
    assert hashlib.sha256(preimage).hexdigest() == secret.data


def test_htlc_example_proof_slot_layout():
    """Blinded keys are the slot 1 and slot 2 table entries.

    The `locktime` tag sits between `pubkeys` and `refund` in the JSON as a
    check that slots are numbered by the canonical `[data, ...pubkeys,
    ...refund]` order, not by tag position.
    """
    secret = P2PKSecret.deserialize(EXAMPLE_HTLC_PROOF["secret"])
    assert secret.kind == SecretKind.HTLC.value
    assert secret.tags.get_tag_all("pubkeys") == [BLINDED_PUBKEY_HEX[1]]
    assert secret.tags.get_tag_all("refund") == [BLINDED_PUBKEY_HEX[2]]
    assert secret.tags.get_tag("locktime") == "1689418329"


def test_htlc_example_proof_derives_slot_1_and_2_keys():
    """Receiver-side derivation at slots 1 and 2 matches the vector tables."""
    p = PrivateKey(bytes.fromhex(P_PRIVKEY_HEX))
    k1 = derive_blinded_private_key(
        privkey=p,
        ephemeral_pubkey_hex=E_PUBKEY_HEX,
        blinded_pubkey_hex=BLINDED_PUBKEY_HEX[1],
        slot_index=1,
    )
    k2 = derive_blinded_private_key(
        privkey=p,
        ephemeral_pubkey_hex=E_PUBKEY_HEX,
        blinded_pubkey_hex=BLINDED_PUBKEY_HEX[2],
        slot_index=2,
    )
    assert k1 is not None
    assert k1.to_hex() == DERIVED_PRIVKEY_HEX[1]
    assert k2 is not None
    assert k2.to_hex() == DERIVED_PRIVKEY_HEX[2]


def test_htlc_example_proof_wallet_derives_receiver_keys():
    """The wallet-level slot numbering derives both receiver keys.

    Pins the slot order against the cashu-ts #763 bug class: the hash lock
    occupies slot 0 unblinded, the `pubkeys` key blinds at slot 1 and the
    `refund` key at slot 2. A wallet that numbers HTLC keys from slot 0
    derives neither key.
    """

    class ReceiverStub(WalletP2BK):
        def __init__(self, private_key: PrivateKey) -> None:
            self.private_key = private_key

    proof = Proof(
        amount=EXAMPLE_HTLC_PROOF["amount"],
        C=EXAMPLE_HTLC_PROOF["C"],
        id=EXAMPLE_HTLC_PROOF["id"],
        secret=EXAMPLE_HTLC_PROOF["secret"],
        p2pk_e=EXAMPLE_HTLC_PROOF["p2pk_e"],
    )
    stub = ReceiverStub(PrivateKey(bytes.fromhex(P_PRIVKEY_HEX)))
    assert [k.to_hex() for k in stub._derive_p2bk_signing_keys(proof)] == [
        DERIVED_PRIVKEY_HEX[1],
        DERIVED_PRIVKEY_HEX[2],
    ]


def test_example_v4_token_decodes_to_example_proofs():
    """The V4 token decodes to the exact P2PK and HTLC example proofs.

    This pins the `pe` field as a 33-byte CBOR bstr and the dleq values as
    32-byte bstrs: if the token carried them as hex strings the assertions
    below would fail.
    """
    token = TokenV4.deserialize(EXAMPLE_V4_TOKEN)
    assert token.mint == "http://localhost:3338"
    assert token.unit == "sat"
    assert token.memo is None
    proofs = token.proofs
    assert len(proofs) == 2
    _assert_proof_matches_example(proofs[0], EXAMPLE_PROOF)
    _assert_proof_matches_example(proofs[1], EXAMPLE_HTLC_PROOF)


def test_example_v4_token_serialization_round_trips():
    """Re-encoding and decoding preserves the P2BK fields exactly.

    Nutshell emits the top-level CBOR map keys in a different order than the
    vector (t, d, m, u vs m, u, t, matching the NUT-00 examples), which every
    decoder accepts, so the round trip is checked semantically rather than
    byte-for-byte.
    """
    token = TokenV4.deserialize(EXAMPLE_V4_TOKEN)
    encoded = token.serialize(include_dleq=True)
    assert encoded.startswith("cashuB")
    token2 = TokenV4.deserialize(encoded)
    assert len(token2.proofs) == 2
    _assert_proof_matches_example(token2.proofs[0], EXAMPLE_PROOF)
    _assert_proof_matches_example(token2.proofs[1], EXAMPLE_HTLC_PROOF)
