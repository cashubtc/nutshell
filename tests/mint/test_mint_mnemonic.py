from typing import Mapping, Optional

import pytest

from cashu.core.base import Method, MintKeyset, Unit
from cashu.core.crypto.keys import derive_bip39_derivation_path, derive_keys_from_seed
from cashu.core.db import Database
from cashu.core.migrations import migrate_databases
from cashu.core.settings import settings
from cashu.lightning.fake import FakeWallet
from cashu.mint import migrations as mint_migrations
from cashu.mint.crud import LedgerCrudSqlite
from cashu.mint.ledger import Ledger

MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
OTHER_MNEMONIC = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"


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


def test_mnemonic_keyset_rejects_other_mnemonic(monkeypatch):
    derivation_path = derive_bip39_derivation_path("sat", 0)
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    keyset = MintKeyset(derivation_path=derivation_path, unit="sat")

    monkeypatch.setattr(settings, "mint_mnemonic", OTHER_MNEMONIC)
    with pytest.raises(Exception, match="was not derived from MINT_MNEMONIC"):
        MintKeyset(derivation_path=derivation_path, unit="sat", id=keyset.id)


def test_invalid_mnemonic_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "mint_mnemonic", " ".join(["abandon"] * 12))
    with pytest.raises(Exception, match="not a valid BIP-39 mnemonic"):
        Ledger(db=Database("mint", str(tmp_path / "mint")), seed=None)


@pytest.mark.asyncio
async def test_mnemonic_mint_activates_a_keyset_per_unit(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "mint_mnemonic", MNEMONIC)
    db = Database("mint", str(tmp_path / "mint"))
    await migrate_databases(db, mint_migrations)
    backends = {
        Method.bolt11: {Unit.sat: FakeWallet(Unit.sat), Unit.usd: FakeWallet(Unit.usd)}
    }

    ledger = await start_ledger(db, None, backends)
    assert {k.unit for k in ledger.keysets.values() if k.active} == {Unit.sat, Unit.usd}
    # each unit's first keyset is at index 1
    assert all(k.derivation_path.endswith("/1'") for k in ledger.keysets.values())

    # a restart loads the same keysets, derived from the mnemonic instead of stored
    restarted = await start_ledger(db, None, backends)
    assert set(restarted.keysets) == set(ledger.keysets)
    assert all(k.from_mnemonic for k in restarted.keysets.values())
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
