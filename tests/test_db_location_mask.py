from cashu.core.db import mask_db_location


def test_mask_db_location_hides_url_credentials():
    masked = mask_db_location("postgresql://user:secret@localhost:5432/mint")
    assert masked == "postgresql://********"


def test_mask_db_location_keeps_sqlite_directory():
    assert mask_db_location("data/mint") == "data/mint"
