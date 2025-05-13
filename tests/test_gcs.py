import os
import random
from cashu.core.gcs import GCSFilter

def test_gcs_filter():
    # Generate random data for testing
    num_items = 100
    item_size = 33  # 33 bytes
    items = [os.urandom(item_size) for _ in range(num_items)]

    # Create a GCS filter
    gcs_filter = GCSFilter.create(items)

    # Test set membership
    results = GCSFilter.match_many(gcs_filter, items, num_items)

    # Assert all items are found in the filter
    assert all(results.values()), "Not all items were found in the GCS filter"

    # Test with a non-existent item
    non_existent_item = os.urandom(item_size)
    results = GCSFilter.match_many(gcs_filter, [non_existent_item], num_items)
    assert not any(results.values()), "Non-existent item was incorrectly found in the GCS filter"
