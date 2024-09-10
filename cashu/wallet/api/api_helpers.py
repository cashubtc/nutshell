from ...core.base import Token
from ...wallet.crud import get_keysets


async def verify_mints(wallet, tokenObj: Token):
    # verify mints
    mint = tokenObj.mint
    mint_keysets = await get_keysets(mint_url=mint, db=wallet.db)
    assert len(mint_keysets), "We don't know this mint."
