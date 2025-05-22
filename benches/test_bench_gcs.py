import os

from cashu.core.gcs import GCSFilter

num_items_arr = [100, 1000, 10000, 100000, 1000000]
item_size = 33

def test_gcs_filter_creation_benchmark_100(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[0])]
    benchmark(GCSFilter.create, items)

def test_gcs_filter_creation_benchmark_1000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[1])]
    benchmark(GCSFilter.create, items)

def test_gcs_filter_creation_benchmark_10000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[2])]
    benchmark(GCSFilter.create, items)

def test_gcs_filter_creation_benchmark_100000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[3])]
    benchmark(GCSFilter.create, items)

def test_gcs_filter_creation_benchmark_1000000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[4])]
    benchmark(GCSFilter.create, items)

'''
def test_hash_to_range_benchmark_100(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[0])]
    f = 784931 * len(items)
    benchmark(lambda: [hash_to_range(item, f) for item in items])

def test_sort_benchmark_100(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[0])]
    f = 784931 * len(items)
    hashed_items = [hash_to_range(item, f) for item in items]

    benchmark(sorted, hashed_items)

def test_hash_to_range_benchmark_1000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[1])]
    f = 784931 * len(items)
    benchmark(lambda: [hash_to_range(item, f) for item in items])

def test_sort_benchmark_1000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[1])]
    f = 784931 * len(items)
    hashed_items = [hash_to_range(item, f) for item in items]

    benchmark(sorted, hashed_items)

def test_hash_to_range_benchmark_10000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[2])]
    f = 784931 * len(items)
    benchmark(lambda: [hash_to_range(item, f) for item in items])

def test_sort_benchmark_10000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[2])]
    f = 784931 * len(items)
    hashed_items = [hash_to_range(item, f) for item in items]

    benchmark(sorted, hashed_items)

def test_hash_to_range_benchmark_100000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[3])]
    f = 784931 * len(items)
    benchmark(lambda: [hash_to_range(item, f) for item in items])

def test_sort_benchmark_100000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[3])]
    f = 784931 * len(items)
    hashed_items = [hash_to_range(item, f) for item in items]

    benchmark(sorted, hashed_items)

def test_hash_to_range_benchmark_1000000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[4])]
    f = 784931 * len(items)
    benchmark(lambda: [hash_to_range(item, f) for item in items])

def test_sort_benchmark_1000000(benchmark):
    items = [os.urandom(item_size) for _ in range(num_items_arr[4])]
    f = 784931 * len(items)
    hashed_items = [hash_to_range(item, f) for item in items]

    benchmark(sorted, hashed_items)
'''