import os
from base64 import b64encode

from cashu.core.gcs import GCSFilter, hash_to_range

items = [
    bytes.fromhex('c2735796c1d45c68e7f03d3ea3bfcf5d6f10e6eb480e57fc3dccaf8ce66990dfc5'),
    bytes.fromhex('3c7ac2a233f8d5439be8cf3109d314e7da476e1ca762dc05f64ca3d5acac2da1fa'),
    bytes.fromhex('73e199a811db202ef7fbb1699b0e4859d15735c8f7f838fd9e50b37dc47c0ff4b9'),
    bytes.fromhex('02f171db2b577f6d586580651da4951c2e1506454bb9b76077d7a9fdb8606cf2f6'),
    bytes.fromhex('106954852453d217ad91e3b14c37bcb6adf62b038cc6a6a281f63edf78de2c7819'),
    bytes.fromhex('621e006de8d41b14491933e695985a730179003846b739224316af578fc49c1ee8'),
    bytes.fromhex('59b759ecda3c4d9027b9fe549fe6ae33b1bf573b9e9c2d0cdf17d20ea38794f1b7'),
    bytes.fromhex('cfcc8745503e9efb67e48b0bee006f6433dec534130707ac23ed4eae911d60eec2'),
    bytes.fromhex('f1d57d98f80e528af885e6174f7cd0ef39c31f8436c66b8f27c848a3497c9a7dfb'),
    bytes.fromhex('5a21aa11ccd643042f3fe3f0fcc02ccfb51c72419c5eab64a3565aa8499aa64cdf')
]

target_filter = '7sdQJ7OweaujLCqS7KDHzu/3pySZrDsatjQA'

def test_gcs_filter():
    # Create a GCS filter
    gcs_filter = GCSFilter.create(items)
    assert b64encode(gcs_filter.content).decode() == target_filter

def test_gcs_filter_membership():
    # Create a GCS filter
    gcs_filter = GCSFilter.create(items)

    # Test set membership
    results = gcs_filter.match_many(items)

    # Assert all items are found in the filter
    assert all(results.values()), "Not all items were found in the GCS filter"

    # Test with a non-existent item
    non_existent_item = os.urandom(33)
    results = gcs_filter.match_many([non_existent_item])
    assert not any(results.values()), "Non-existent item was incorrectly found in the GCS filter"

def test_hash_to_range():
    test_item = bytes.fromhex('00000000')
    test_range = 784931 * 1000
    hashed = hash_to_range(test_item, test_range)
    assert hashed == 108500230