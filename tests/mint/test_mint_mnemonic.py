from typing import Mapping, Optional

import pytest

from cashu.core.base import BlindedMessage, Method, MintKeyset, Proof, Unit
from cashu.core.crypto import b_dhke, bls_dhke
from cashu.core.crypto.bls import PublicKey as BlsPublicKey
from cashu.core.crypto.keys import derive_bip39_derivation_path, derive_keys_from_seed
from cashu.core.crypto.secp import PrivateKey, PublicKey
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.lightning.fake import FakeWallet
from cashu.mint import migrations as mint_migrations
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
OTHER_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
LEGACY_KEYSET_ID = "018e844b6ba9abd3e6049756fba8cc638dfd3e4f4c9959aacd04e55c62603d061b"
V3_KEYSET_ID = "022e7060b93077574e2d4c65fbdf0554d61746ec6264aece5724abce922eba29a7"


async def start_ledger(db: Database, seed: Optional[str], backends: Mapping) -> Ledger:
    ledger = Ledger(db=db, seed=seed, backends=backends, crud=LedgerCrudSqlite())
    await ledger._startup_keysets()
    return ledger


def test_bip39_keys_test_vectors():
    # vector from CDK's mint_mod_generate_keyset_from_seed test
    seed = bytes.fromhex("00" * 31 + "01")
    keys = derive_keys_from_seed(seed, derive_bip39_derivation_path("sat", 0), [1, 2])
    assert (
        keys[1].public_key.format().hex()
        == "0380a4bb98d9bc5d5b11c7cf2b705dbc894b62ac99cf67e0ef1a3d47ea6dc54706"
    )
    assert (
        keys[2].public_key.format().hex()
        == "022fe5e50a15d721014b538ca6a3ff20ee049b195ba0b1705f64829da8779b6940"
    )


@pytest.mark.parametrize("version", ["0.22.0", "0.22.1", "0.22.99"])
def test_pre_0_23_mnemonic_keysets_preserve_v2_keys(monkeypatch, version):
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    keyset = MintKeyset(
        derivation_path=derive_bip39_derivation_path("sat", 0),
        unit="sat",
        amounts=[1, 2],
        version=version,
    )

    assert keyset.id == LEGACY_KEYSET_ID
    assert keyset.public_keys_hex[1] == (
        "03f154a2e6ff04df1e9aa0cff884a68ebb81a2a308da2d97cb3e2ab1febcee8d91"
    )
    assert all(len(key) == 66 for key in keyset.public_keys_hex.values())


@pytest.mark.parametrize("version", [None, "0.23.0", "0.23.1", "0.24.0"])
def test_mnemonic_keysets_from_0_23_use_v3_keys(monkeypatch, version):
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    keyset = MintKeyset(
        derivation_path=derive_bip39_derivation_path("sat", 0),
        unit="sat",
        amounts=[1, 2],
        version=version,
    )

    assert keyset.id == V3_KEYSET_ID
    assert keyset.public_keys_hex[1] == (
        "94674ad38798a25708353969806e526689aaebecb038df998e9544a9dcfadde9464"
        "cd9d9da334195a4989be11a8a02be19ffed5bc8794258ea6339c0f033c999829e"
        "2414d1c7891d9dda8a665258dd281cde4b7c2c0737ce684b8e607c11bb76"
    )
    assert all(len(key) == 192 for key in keyset.public_keys_hex.values())


@pytest.mark.parametrize("version", ["0.22.1", "0.23.0"])
def test_mnemonic_keyset_rejects_other_mnemonic(monkeypatch, version):
    derivation_path = derive_bip39_derivation_path("sat", 0)
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    keyset = MintKeyset(derivation_path=derivation_path, unit="sat", version=version)

    monkeypatch.setattr(settings, "mint_mnemonic", OTHER_MNEMONIC)
    with pytest.raises(Exception, match="was not derived from MINT_MNEMONIC"):
        MintKeyset(
            derivation_path=derivation_path, unit="sat", id=keyset.id, version=version
        )


def test_invalid_mnemonic_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "mint_mnemonic", " ".join(["abandon"] * 12))
    with pytest.raises(Exception, match="not a valid BIP-39 mnemonic"):
        Ledger(db=Database("mint", str(tmp_path / "mint")), seed=None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "version, prefix, key_length", [("0.22.1", "01", 66), ("0.23.0", "02", 192)]
)
async def test_mnemonic_mint_activates_a_keyset_per_unit(
    tmp_path, monkeypatch, version, prefix, key_length
):
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    monkeypatch.setattr(settings, "version", version)
    db = Database("mint", str(tmp_path / "mint"))
    await migrate_databases(db, mint_migrations)
    backends = {
        Method.bolt11: {Unit.sat: FakeWallet(Unit.sat), Unit.usd: FakeWallet(Unit.usd)}
    }

    ledger = await start_ledger(db, None, backends)
    assert {k.unit for k in ledger.keysets.values() if k.active} == {Unit.sat, Unit.usd}
    # each unit's first keyset is at index 1
    assert all(k.derivation_path.endswith("/1'") for k in ledger.keysets.values())
    assert all(k.id.startswith(prefix) for k in ledger.keysets.values())
    assert all(
        len(key) == key_length
        for keyset in ledger.keysets.values()
        for key in keyset.public_keys_hex.values()
    )
    original_keys = {k.id: k.public_keys_hex for k in ledger.keysets.values()}

    # a restart loads the same keysets, derived from the mnemonic instead of stored
    restarted = await start_ledger(db, None, backends)
    assert set(restarted.keysets) == set(ledger.keysets)
    assert all(k.from_mnemonic for k in restarted.keysets.values())
    assert {k.id: k.public_keys_hex for k in restarted.keysets.values()} == original_keys
    await db.engine.dispose()


@pytest.mark.asyncio
async def test_rotation_switches_unit_to_mnemonic(ledger: Ledger, monkeypatch):
    # a legacy mint that bumped its derivation path signs with two sat keysets
    await ledger.activate_keyset(derivation_path="m/0'/0'/1'")
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)

    # setting the mnemonic does not rotate any keyset at startup
    mnemonic_ledger = await start_ledger(
        ledger.db, settings.mint_private_key, ledger.backends
    )
    assert set(mnemonic_ledger.keysets) == set(ledger.keysets)

    keyset = await mnemonic_ledger.rotate_next_keyset(Unit.sat)
    assert keyset.from_mnemonic
    assert keyset.version == "0.23.0"
    assert keyset.id.startswith("02")

    # a unit without an active keyset can't be rotated
    with pytest.raises(Exception, match="Couldn't find suitable keyset"):
        await mnemonic_ledger.rotate_next_keyset(Unit.eur)

    # after a restart, sat only signs with the new keyset and usd is untouched
    restarted = await start_ledger(
        ledger.db, settings.mint_private_key, ledger.backends
    )
    active = [k for k in restarted.keysets.values() if k.active]
    assert [k.id for k in active if k.unit == Unit.sat] == [keyset.id]
    assert [k.from_mnemonic for k in active if k.unit == Unit.usd] == [False]


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["0.22.0", "0.22.1", "0.22.99"])
async def test_mnemonic_keysets_reload_and_rotate_after_0_23_upgrade(
    tmp_path, monkeypatch, version
):
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    monkeypatch.setattr(settings, "version", version)
    db = Database("mint", str(tmp_path / "mint"))
    backends = {Method.bolt11: {Unit.sat: FakeWallet(Unit.sat)}}
    try:
        await migrate_databases(db, mint_migrations)
        ledger = await start_ledger(db, None, backends)
        legacy = ledger.keyset
        original_keys = legacy.public_keys_hex
        assert legacy.id.startswith("01")

        secret = "mnemonic proof issued before upgrade"
        blinded, r = b_dhke.step1_alice(secret)
        outputs = [BlindedMessage(amount=1, id=legacy.id, B_=blinded.format().hex())]
        await ledger._store_blinded_messages(outputs)
        promises = await ledger._sign_blinded_messages(outputs)
        signature = b_dhke.step3_alice(
            PublicKey(bytes.fromhex(promises[0].C_)),
            r,
            PublicKey(bytes.fromhex(original_keys[1])),
        )
        proof = Proof(amount=1, id=legacy.id, secret=secret, C=signature.format().hex())

        monkeypatch.setattr(settings, "version", "0.23.0")
        restarted = await start_ledger(db, None, backends)
        assert restarted.keyset.id == legacy.id
        assert restarted.keyset.version == version
        assert restarted.keyset.public_keys_hex == original_keys
        await restarted._verify_inputs([proof])

        new_keyset = await restarted.rotate_next_keyset(Unit.sat, max_order=2)
        assert new_keyset.version == "0.23.0"
        assert new_keyset.id.startswith("02")
        assert not restarted.keysets[legacy.id].active

        secret_v3 = PrivateKey(bytes.fromhex("00" * 31 + "01")).public_key.format().hex()
        blinded_v3, r_v3 = bls_dhke.step1_alice(secret_v3)
        outputs_v3 = [
            BlindedMessage(amount=1, id=new_keyset.id, B_=blinded_v3.format().hex())
        ]
        await restarted._store_blinded_messages(outputs_v3)
        promises_v3 = await restarted._sign_blinded_messages(outputs_v3)
        public_key_v3 = BlsPublicKey(
            bytes.fromhex(new_keyset.public_keys_hex[1]), group="G2"
        )
        signature_v3 = bls_dhke.step3_alice(
            BlsPublicKey(bytes.fromhex(promises_v3[0].C_)), r_v3, public_key_v3
        )
        assert bls_dhke.pairing_verification(public_key_v3, signature_v3, secret_v3)

        reloaded = await start_ledger(db, None, backends)
        assert reloaded.keyset.id == new_keyset.id
        assert reloaded.keyset.public_keys_hex == new_keyset.public_keys_hex
        assert reloaded.keysets[legacy.id].public_keys_hex == original_keys
        await reloaded._verify_inputs([proof])
    finally:
        await db.engine.dispose()
