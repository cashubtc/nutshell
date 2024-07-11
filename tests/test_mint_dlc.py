import pytest
from hashlib import sha256
from random import shuffle, randint

from cashu.core.crypto.dlc import sorted_merkle_hash, merkle_root, merkle_verify

@pytest.mark.asyncio
async def test_merkle_hash():
    data = [b'\x01', b'\x02']
    target = '25dfd29c09617dcc9852281c030e5b3037a338a4712a42a21c907f259c6412a0'
    h = sorted_merkle_hash(data[1], data[0])
    assert h.hex() == target, f'sorted_merkle_hash test fail: {h.hex() = }'
    h = sorted_merkle_hash(data[0], data[1])
    assert h.hex() == target, f'sorted_merkle_hash reverse test fail: {h.hex() = }'

@pytest.mark.asyncio
async def test_merkle_root():
    target = '0ee849f3b077380cd2cf5c76c6d63bcaa08bea89c1ef9914e5bc86c174417cb3'
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, _ = merkle_root(leafs)
    assert root.hex() == target, f"merkle_root test fail: {root.hex() = }"

@pytest.mark.asyncio
async def test_merkle_verify():
    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(16)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(53)]
    root, branch_hashes = merkle_root(leafs, 0)
    assert merkle_verify(root, leafs[0], branch_hashes), "merkle_verify test fail"

    leafs = [sha256(i.to_bytes(32, 'big')).digest() for i in range(18)]
    shuffle(leafs)
    l = randint(0, len(leafs)-1)
    root, branch_hashes = merkle_root(leafs, l)
    assert merkle_verify(root, leafs[l], branch_hashes), "merkle_verify test fail"
