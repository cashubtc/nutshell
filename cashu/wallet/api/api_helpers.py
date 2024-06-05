from ...core.base import TokenV3
from ...wallet.crud import get_keysets


async def verify_mints(wallet, tokenObj: TokenV3):
    # verify mints
    mints = set([t.mint for t in tokenObj.token])
    if None in mints:
        raise Exception("Token has missing mint information.")
    for mint in mints:
        assert mint
        mint_keysets = await get_keysets(mint_url=mint, db=wallet.db)
        assert len(mint_keysets), "We don't know this mint."
