import pytest
import pytest_asyncio

from cashu.core.crypto.dlc import sorted_merkle_hash

@pytest.mark.asyncio
async def test_sorted_merkle_hash():
    data = [b'\x01', b'\x02']
    target = '25dfd29c09617dcc9852281c030e5b3037a338a4712a42a21c907f259c6412a0'
    h = sorted_merkle_hash(data[1], data[0])
    assert h.hex() == target, f'sorted_merkle_hash test fail: {h.hex() = }'
    h = sorted_merkle_hash(data[0], data[1])
    assert h.hex() == target, f'sorted_merkle_hash test fail: {h.hex() = }'