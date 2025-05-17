import os
from cashu.core.gcs import GCSFilter

def test_gcs_filter_creation_benchmark(benchmark):
    num_items = 100000
    item_size = 33  # 33 bytes
    items = [os.urandom(item_size) for _ in range(num_items)]

    benchmark(GCSFilter.create, items)

def test_gcs_filter_match_benchmark(benchmark):
    num_items = 100000
    item_size = 33  # 33 bytes
    items = [os.urandom(item_size) for _ in range(num_items)]
    gcs_filter = GCSFilter.create(items)

    benchmark(GCSFilter.match_many, gcs_filter, items, num_items)
