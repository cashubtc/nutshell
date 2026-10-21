import pytest

from cashu.core.db import mask_db_location


@pytest.mark.parametrize("scheme", ["postgres", "postgresql"])
def test_mask_db_location_hides_url_credentials(scheme):
    masked = mask_db_location(f"{scheme}://user:secret@localhost:5432/mint")
    assert masked == f"{scheme}://********"


def test_mask_db_location_keeps_sqlite_directory():
    assert mask_db_location("data/mint") == "data/mint"
