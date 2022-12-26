import os

import click

from cashu.core.base import Proof
from cashu.core.settings import CASHU_DIR
from cashu.wallet.crud import get_keyset
from cashu.wallet.wallet import Wallet as Wallet


async def verify_mints(ctx, dtoken):
    trust_token_mints = True
    for mint_id in dtoken.get("mints"):
        for keyset in set(dtoken["mints"][mint_id]["ks"]):
            mint_url = dtoken["mints"][mint_id]["url"]
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )
            # make sure that this mint supports this keyset
            mint_keysets = await keyset_wallet._get_keysets(mint_url)
            assert keyset in mint_keysets["keysets"], "mint does not have this keyset."

            # we validate the keyset id by fetching the keys from the mint
            mint_keyset = await keyset_wallet._get_keyset(mint_url, keyset)
            assert keyset == mint_keyset.id, Exception("keyset not valid.")

            # we check the db whether we know this mint already and ask the user if not
            mint_keysets = await get_keyset(mint_url=mint_url, db=keyset_wallet.db)
            if mint_keysets is None:
                # we encountered a new mint and ask for a user confirmation
                trust_token_mints = False
                print("")
                print("Warning: Tokens are from a mint you don't know yet.")
                print("\n")
                print(f"Mint URL: {mint_url}")
                print(f"Mint keyset: {keyset}")
                print("\n")
                click.confirm(
                    f"Do you trust this mint and want to receive the tokens?",
                    abort=True,
                    default=True,
                )
                trust_token_mints = True

    assert trust_token_mints, Exception("Aborted!")


async def redeem_multimint(ctx, dtoken, script, signature):
    # we get the mint information in the token and load the keys of each mint
    # we then redeem the tokens for each keyset individually
    for mint_id in dtoken.get("mints"):
        for keyset in set(dtoken["mints"][mint_id]["ks"]):
            mint_url = dtoken["mints"][mint_id]["url"]
            # init a temporary wallet object
            keyset_wallet = Wallet(
                mint_url, os.path.join(CASHU_DIR, ctx.obj["WALLET_NAME"])
            )

            # load the keys
            await keyset_wallet.load_mint(keyset_id=keyset)

            # redeem proofs of this keyset
            redeem_proofs = [
                Proof(**p) for p in dtoken["tokens"] if Proof(**p).id == keyset
            ]
            _, _ = await keyset_wallet.redeem(
                redeem_proofs, scnd_script=script, scnd_siganture=signature
            )
