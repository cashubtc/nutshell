import asyncio
import datetime

import pytest

from cashu.core.settings import settings
from cashu.mint.ledger import Ledger


@pytest.mark.asyncio
async def test_should_rotate_keyset_behavior(ledger: Ledger):
    # Get any active keyset
    keyset = next(k for k in ledger.keysets.values() if k.active)

    # By default, freshly created keyset should not rotate
    assert not ledger.should_rotate_keyset(keyset)

    # If keyset is inactive, it should never rotate
    keyset.active = False
    assert not ledger.should_rotate_keyset(keyset)
    keyset.active = True

    # If valid_from is mocked in the far past, it should rotate
    original_valid_from = keyset.valid_from
    keyset.valid_from = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=31)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    assert ledger.should_rotate_keyset(keyset)

    # Restore
    keyset.valid_from = original_valid_from


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_flow(ledger: Ledger):
    # Set a very short rotation interval
    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled

    try:
        settings.mint_keyset_rotation_enabled = True
        settings.mint_keyset_rotation_interval_seconds = 1

        # Keep track of active keysets before rotation
        active_keysets_before = {
            k.unit: k for k in ledger.keysets.values() if k.active
        }
        assert len(active_keysets_before) > 0

        # Wait to exceed the 1 second interval
        await asyncio.sleep(1.5)

        # Trigger automatic rotation check
        await ledger.rotate_keysets_if_needed()

        # Get active keysets after rotation
        active_keysets_after = {
            k.unit: k for k in ledger.keysets.values() if k.active
        }

        for unit, old_keyset in active_keysets_before.items():
            new_keyset = active_keysets_after[unit]
            # Verify a new keyset has been created and it differs from the old one
            assert old_keyset.id != new_keyset.id

            # Verify the old keyset is now inactive in memory and DB
            assert not old_keyset.active
            db_old_keysets = await ledger.crud.get_keyset(db=ledger.db, id=old_keyset.id)
            assert len(db_old_keysets) == 1
            assert not db_old_keysets[0].active

            # Verify new keyset is active in memory and DB
            assert new_keyset.active
            db_new_keysets = await ledger.crud.get_keyset(db=ledger.db, id=new_keyset.id)
            assert len(db_new_keysets) == 1
            assert db_new_keysets[0].active

            # Verify key parameters are preserved
            assert new_keyset.input_fee_ppk == old_keyset.input_fee_ppk
            assert len(new_keyset.amounts) == len(old_keyset.amounts)

            # Verify derivation path counter has incremented
            old_path = old_keyset.derivation_path.split("/")
            new_path = new_keyset.derivation_path.split("/")
            assert old_path[:-1] == new_path[:-1]
            assert int(new_path[-1].replace("'", "")) - int(old_path[-1].replace("'", "")) == 1

    finally:
        # Restore settings
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_disabled(ledger: Ledger):
    # Keep track of active keyset
    keyset = next(k for k in ledger.keysets.values() if k.active)

    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled

    try:
        settings.mint_keyset_rotation_enabled = False
        settings.mint_keyset_rotation_interval_seconds = 1

        # Wait to exceed interval
        await asyncio.sleep(1.5)

        # Trigger check (should do nothing since disabled)
        await ledger.rotate_keysets_if_needed()

        # Get active keyset for the same unit
        active_keysets = [k for k in ledger.keysets.values() if k.active and k.unit == keyset.unit]
        assert len(active_keysets) == 1
        assert active_keysets[0].id == keyset.id
        assert active_keysets[0].active

    finally:
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled
