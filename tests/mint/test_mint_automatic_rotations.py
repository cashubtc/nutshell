import asyncio
import datetime
import time

import pytest

from cashu.core.base import MintKeyset, Unit
from cashu.core.settings import settings
from cashu.mint.ledger import Ledger
from cashu.mint.startup import ledger as global_ledger


@pytest.fixture(autouse=True)
def disable_global_ledger_rotation():
    original_method = global_ledger.rotate_keysets_if_needed

    async def noop_rotate(*args, **kwargs):
        pass

    global_ledger.rotate_keysets_if_needed = noop_rotate
    yield
    global_ledger.rotate_keysets_if_needed = original_method


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
    original_interval = settings.mint_keyset_rotation_interval_seconds
    settings.mint_keyset_rotation_interval_seconds = 2592000  # 30 days
    try:
        original_valid_from = keyset.valid_from
        keyset.valid_from = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=31)
        ).strftime("%Y-%m-%d %H:%M:%S")
        assert ledger.should_rotate_keyset(keyset)
    finally:
        # Restore
        keyset.valid_from = original_valid_from
        settings.mint_keyset_rotation_interval_seconds = original_interval


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_flow(ledger: Ledger):
    # Cancel background tasks to avoid race conditions with manual triggering
    for task in ledger.regular_tasks:
        task.cancel()
    ledger.regular_tasks = []

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
            db_old_keysets = await ledger.crud.get_keyset(
                db=ledger.db, id=old_keyset.id
            )
            assert len(db_old_keysets) == 1
            assert not db_old_keysets[0].active

            # Verify new keyset is active in memory and DB
            assert new_keyset.active
            db_new_keysets = await ledger.crud.get_keyset(
                db=ledger.db, id=new_keyset.id
            )
            assert len(db_new_keysets) == 1
            assert db_new_keysets[0].active

            # Verify key parameters are preserved
            assert new_keyset.input_fee_ppk == old_keyset.input_fee_ppk
            assert len(new_keyset.amounts) == len(old_keyset.amounts)

            # Verify derivation path counter has incremented
            old_path = old_keyset.derivation_path.split("/")
            new_path = new_keyset.derivation_path.split("/")
            assert old_path[:-1] == new_path[:-1]
            assert (
                int(new_path[-1].replace("'", ""))
                - int(old_path[-1].replace("'", ""))
                == 1
            )

            # If the rotated unit matches the default keyset's unit, verify that
            # the default keyset and derivation path are updated on the ledger
            if unit == ledger.keyset.unit:
                assert ledger.keyset.id == new_keyset.id
                assert ledger.derivation_path == new_keyset.derivation_path

    finally:
        # Restore settings
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_disabled(ledger: Ledger):
    # Cancel background tasks to avoid race conditions with manual triggering
    for task in ledger.regular_tasks:
        task.cancel()
    ledger.regular_tasks = []

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
        active_keysets = [
            k
            for k in ledger.keysets.values()
            if k.active and k.unit == keyset.unit
        ]
        assert len(active_keysets) == 1
        assert active_keysets[0].id == keyset.id
        assert active_keysets[0].active

    finally:
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_preserves_grace_period(ledger: Ledger):
    # Cancel background tasks to avoid race conditions with manual triggering
    for task in ledger.regular_tasks:
        task.cancel()
    ledger.regular_tasks = []

    # Get any active keyset
    keyset = next(k for k in ledger.keysets.values() if k.active)

    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled

    try:
        settings.mint_keyset_rotation_enabled = True
        settings.mint_keyset_rotation_interval_seconds = 1

        # Set a mock final_expiry on the old keyset
        keyset.final_expiry = 2000000000

        # Generate the timestamp 5 seconds ago using the database's format to avoid timezone shifts
        past_ts = int(time.time() - 5)
        keyset.valid_from = ledger.db.timestamp_from_seconds(past_ts)

        # Trigger automatic rotation check
        await ledger.rotate_keysets_if_needed()

        # Retrieve the new active keyset for this unit
        new_keyset = next(
            k
            for k in ledger.keysets.values()
            if k.active and k.unit == keyset.unit
        )

        # Verify a rotation occurred
        assert keyset.id != new_keyset.id

        # Expected new final_expiry should be original final_expiry (2000000000) + active_duration (approx 5)
        assert new_keyset.final_expiry is not None
        assert 2000000004 <= new_keyset.final_expiry <= 2000000008

    finally:
        # Restore settings
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_automatic_keyset_rotation_background(ledger: Ledger):
    # Keep track of original settings
    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled
    original_tasks_interval = settings.mint_regular_tasks_interval_seconds

    try:
        # Set configuration so that background tasks and keyset rotations run very frequently
        settings.mint_keyset_rotation_enabled = True
        settings.mint_keyset_rotation_interval_seconds = 1
        settings.mint_regular_tasks_interval_seconds = 2  # Check every 2 seconds

        # Cancel existing regular tasks so we can restart with the new interval
        for task in ledger.regular_tasks:
            task.cancel()
        ledger.regular_tasks = []

        # Start a new regular tasks loop with the updated 2-second interval
        ledger.regular_tasks.append(asyncio.create_task(ledger._run_regular_tasks()))

        # Keep track of active keysets before background rotation
        active_keysets_before = {
            k.unit: k for k in ledger.keysets.values() if k.active
        }
        assert len(active_keysets_before) > 0

        # Wait to exceed the rotation interval and allow the background task to run
        # Keyset rotation interval is 1s, and task runs every 2s, so 2.5s is plenty of time
        # for exactly one background rotation to run and complete.
        await asyncio.sleep(2.5)

        # Get active keysets after background rotation
        active_keysets_after = {
            k.unit: k for k in ledger.keysets.values() if k.active
        }

        # Verify background rotation occurred successfully
        for unit, old_keyset in active_keysets_before.items():
            new_keyset = active_keysets_after[unit]
            assert old_keyset.id != new_keyset.id
            assert not old_keyset.active
            assert new_keyset.active

            # If the rotated unit matches the default keyset's unit, verify that
            # the default keyset and derivation path are updated on the ledger
            if unit == ledger.keyset.unit:
                assert ledger.keyset.id == new_keyset.id
                assert ledger.derivation_path == new_keyset.derivation_path

    finally:
        # Restore settings and restart original tasks loop
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled
        settings.mint_regular_tasks_interval_seconds = original_tasks_interval

        for task in ledger.regular_tasks:
            task.cancel()
        ledger.regular_tasks = []
        ledger.regular_tasks.append(asyncio.create_task(ledger._run_regular_tasks()))


@pytest.mark.asyncio
async def test_regression_non_atomic_rotation(ledger: Ledger):
    """
    Regression test: rotation is not atomic.
    Verifies that if update_keyset fails, the entire transaction is rolled back.
    The new keyset is not saved, and only the old active keyset remains in DB.
    """
    for task in ledger.regular_tasks:
        task.cancel()
    ledger.regular_tasks = []

    # Get active keyset and set its valid_from to the past
    keyset = next(k for k in ledger.keysets.values() if k.active)
    original_valid_from = keyset.valid_from
    keyset.valid_from = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    ).strftime("%Y-%m-%d %H:%M:%S")

    original_update_keyset = ledger.crud.update_keyset

    async def mock_update_keyset(*args, **kwargs):
        raise Exception("Simulated DB crash/disconnection during update_keyset")

    ledger.crud.update_keyset = mock_update_keyset

    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled

    try:
        settings.mint_keyset_rotation_enabled = True
        settings.mint_keyset_rotation_interval_seconds = 1

        # Trigger rotation check. This will catch and suppress the Exception we raise in update_keyset
        await ledger.rotate_keysets_if_needed()

        # Due to transactional rollback, the new keyset should NOT have been stored in the DB,
        # and the old keyset should still be active.
        db_all_keysets = await ledger.crud.get_keyset(db=ledger.db)
        active_db_keysets = [k for k in db_all_keysets if k.active and k.unit == keyset.unit]

        # There should be exactly ONE active keyset for this unit (the old one)
        assert len(active_db_keysets) == 1, f"Expected exactly 1 active keyset in DB, found: {len(active_db_keysets)}"
        assert active_db_keysets[0].id == keyset.id, "The active keyset should be the original one"

    finally:
        ledger.crud.update_keyset = original_update_keyset
        keyset.valid_from = original_valid_from
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_regression_concurrent_rotation_race(ledger: Ledger):
    """
    Regression test: concurrent instances/manual rotation can race.
    Verifies that with locks and deactivation status checks, concurrent rotation requests
    safely serialize. The second request detects that the keyset was already rotated and skips gracefully,
    raising no exceptions.
    """
    for task in ledger.regular_tasks:
        task.cancel()
    ledger.regular_tasks = []

    keyset = next(k for k in ledger.keysets.values() if k.active)
    original_valid_from = keyset.valid_from
    keyset.valid_from = (
        datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=365)
    ).strftime("%Y-%m-%d %H:%M:%S")

    original_interval = settings.mint_keyset_rotation_interval_seconds
    original_enabled = settings.mint_keyset_rotation_enabled

    try:
        settings.mint_keyset_rotation_enabled = True
        settings.mint_keyset_rotation_interval_seconds = 1

        # Run two concurrent rotations passing active_keyset_id
        results = await asyncio.gather(
            ledger.rotate_next_keyset(unit=keyset.unit, active_keyset_id=keyset.id),
            ledger.rotate_next_keyset(unit=keyset.unit, active_keyset_id=keyset.id),
            return_exceptions=True
        )

        # Neither of them should raise an exception (both return a valid MintKeyset)
        exceptions = [res for res in results if isinstance(res, Exception)]
        assert len(exceptions) == 0, f"Expected no exceptions, but got: {exceptions}"

        # Both results should be MintKeysets and they should be identical (the same rotated keyset)
        assert results[0].id == results[1].id, "Expected both parallel tasks to return the same rotated keyset ID"

    finally:
        keyset.valid_from = original_valid_from
        settings.mint_keyset_rotation_interval_seconds = original_interval
        settings.mint_keyset_rotation_enabled = original_enabled


@pytest.mark.asyncio
async def test_regression_highest_counter_selection_incomplete(ledger: Ledger):
    """
    Regression test: highest-counter selection is incomplete.
    Verifies that selected_keyset_counter is updated properly and the keyset with the
    absolute highest counter is selected for rotation.
    """
    # Create dummy active keysets with different counters
    keyset_high = MintKeyset(
        derivation_path="m/0/0/0/5'",
        seed=ledger.seed,
        amounts=ledger.amounts,
        active=True,
        unit="sat",
    )
    keyset_low_after = MintKeyset(
        derivation_path="m/0/0/0/2'",
        seed=ledger.seed,
        amounts=ledger.amounts,
        active=True,
        unit="sat",
    )
    keyset_medium_after = MintKeyset(
        derivation_path="m/0/0/0/4'",
        seed=ledger.seed,
        amounts=ledger.amounts,
        active=True,
        unit="sat",
    )

    # Backup original active keysets for Unit.sat to restore later
    original_keysets = dict(ledger.keysets)
    try:
        # Clear out other active keysets for Unit.sat
        for k_id, k in list(ledger.keysets.items()):
            if k.unit == Unit.sat:
                ledger.keysets.pop(k_id)

        # Add them in order: High counter first, then lower ones.
        ledger.keysets[keyset_high.id] = keyset_high
        ledger.keysets[keyset_low_after.id] = keyset_low_after
        ledger.keysets[keyset_medium_after.id] = keyset_medium_after

        # Mock database writes so we don't pollute the DB during unit test
        original_store = ledger.crud.store_keyset
        original_update = ledger.crud.update_keyset
        
        async def mock_noop(*args, **kwargs):
            pass
            
        ledger.crud.store_keyset = mock_noop
        ledger.crud.update_keyset = mock_noop

        try:
            rotated_keyset = await ledger.rotate_next_keyset(unit=Unit.sat)
            
            # Since high counter (5) is correctly selected, the new counter should be 5 + 1 = 6.
            rotated_counter = int(rotated_keyset.derivation_path.split("/")[-1].replace("'", ""))
            assert rotated_counter == 6, f"Expected rotated counter to be 6, got {rotated_counter}"

        finally:
            ledger.crud.store_keyset = original_store
            ledger.crud.update_keyset = original_update

    finally:
        ledger.keysets = original_keysets

