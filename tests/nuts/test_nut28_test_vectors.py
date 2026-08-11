import json

import pytest

from cashu.core.base import Proof
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.p2bk import (
    blind_pubkeys,
    derive_blinded_private_key,
    derive_blinding_scalar,
    ecdh_shared_secret,
)


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
