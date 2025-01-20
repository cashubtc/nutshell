import base64

from loguru import logger

from ..core.crypto.keys import derive_keyset_id
from ..core.db import Database
from ..core.settings import settings
from .crud import (
    get_keysets,
    update_keyset,
)
from .protocols import SupportsDb, SupportsMintURL


class WalletCompat(SupportsDb, SupportsMintURL):
    db: Database

    async def inactivate_base64_keysets(self, force_old_keysets: bool) -> None:
        # BEGIN backwards compatibility: phase out keysets with base64 ID by treating them as inactive
        if settings.wallet_inactivate_base64_keysets and not force_old_keysets:
            keysets_in_db = await get_keysets(mint_url=self.url, db=self.db)
            for keyset in keysets_in_db:
                if not keyset.active:
                    continue
                # test if the keyset id is a hex string, if not it's base64
                try:
                    int(keyset.id, 16)
                except ValueError:
                    # verify that it's base64
                    try:
                        _ = base64.b64decode(keyset.id)
                    except ValueError:
                        logger.error("Unexpected: keyset id is neither hex nor base64.")
                        continue

                    # verify that we have a hex version of the same keyset by comparing public keys
                    hex_keyset_id = derive_keyset_id(keys=keyset.public_keys)
                    if hex_keyset_id not in [k.id for k in keysets_in_db]:
                        logger.warning(
                            f"Keyset {keyset.id} is base64 but we don't have a hex version. Ignoring."
                        )
                        continue

                    logger.warning(
                        f"Keyset {keyset.id} is base64 and has a hex counterpart, setting inactive."
                    )
                    keyset.active = False
                    await update_keyset(keyset=keyset, db=self.db)
        # END backwards compatibility
