import base64
import hashlib
import os
from typing import List, Optional, Tuple

from bip32 import BIP32
from loguru import logger
from mnemonic import Mnemonic

from ..core.crypto.secp import PrivateKey
from ..core.db import Database
from ..core.settings import settings
from ..wallet.crud import (
    bump_secret_derivation,
    get_seed_and_mnemonic,
    store_seed_and_mnemonic,
)
from .protocols import SupportsDb, SupportsKeysets


class WalletSecrets(SupportsDb, SupportsKeysets):
    keyset_id: str
    db: Database

    async def _init_private_key(self, from_mnemonic: Optional[str] = None) -> None:
        """Initializes the private key of the wallet from the mnemonic.
        There are three ways to initialize the private key:
        1. If the database does not contain a seed, and no mnemonic is given, a new seed is generated.
        2. If the database does not contain a seed, and a mnemonic is given, the seed is generated from the mnemonic.
        3. If the database contains a seed, the seed is loaded from the database.

        If the mnemonic was not loaded from the database, the seed and mnemonic are stored in the database.

        Args:
            from_mnemonic (Optional[str], optional): Mnemonic to use. Defaults to None.

        Raises:
            ValueError: If the mnemonic is not BIP39 compliant.
        """
        ret_db = await get_seed_and_mnemonic(self.db)

        mnemo = Mnemonic("english")

        if ret_db is None and from_mnemonic is None:
            # if there is no seed in the database, generate a new one
            mnemonic_str = mnemo.generate()
            wallet_command_prefix_str = (
                f" --wallet {settings.wallet_name}"
                if settings.wallet_name != "wallet"
                else ""
            )
            wallet_name = (
                f' for wallet "{settings.wallet_name}"'
                if settings.wallet_name != "wallet"
                else ""
            )
            print(
                f"Generated a new mnemonic{wallet_name}. To view it, run"
                f' "cashu{wallet_command_prefix_str} info --mnemonic".'
            )
        elif from_mnemonic:
            # or use the one provided
            mnemonic_str = from_mnemonic.lower().strip()
        elif ret_db is not None:
            # if there is a seed in the database, use it
            _, mnemonic_str = ret_db[0], ret_db[1]
        else:
            logger.debug("No mnemonic provided")
            return

        if not mnemo.check(mnemonic_str):
            raise ValueError("Invalid mnemonic")

        self.seed = mnemo.to_seed(mnemonic_str)
        self.mnemonic = mnemonic_str

        # logger.debug(f"Using seed: {self.seed.hex()}")
        # logger.debug(f"Using mnemonic: {mnemonic_str}")

        # if no mnemonic was in the database, store the new one
        if ret_db is None:
            await store_seed_and_mnemonic(
                self.db, seed=self.seed.hex(), mnemonic=mnemonic_str
            )

        try:
            self.bip32 = BIP32.from_seed(self.seed)
            self.private_key = PrivateKey(
                self.bip32.get_privkey_from_path("m/129372'/0'/0'/0'")
            )
        except ValueError:
            raise ValueError("Invalid seed")
        except Exception as e:
            logger.error(e)

    async def _generate_secret(self) -> str:
        """Returns base64 encoded deterministic random string.

        NOTE: This method should probably retire after `deterministic_secrets`. We are
        deriving secrets from a counter but don't store the respective blinding factor.
        We won't be able to restore any ecash generated with these secrets.
        """
        # secret_counter = await bump_secret_derivation(db=self.db, keyset_id=keyset_id)
        # logger.trace(f"secret_counter: {secret_counter}")
        # s, _, _ = await self.generate_determinstic_secret(secret_counter, keyset_id)
        # # return s.decode("utf-8")
        # return hashlib.sha256(s).hexdigest()

        # return random 32 byte hex string
        return hashlib.sha256(os.urandom(32)).hexdigest()

    async def generate_determinstic_secret(
        self, counter: int
    ) -> Tuple[bytes, bytes, str]:
        """
        Determinstically generates two secrets (one as the secret message,
        one as the blinding factor).
        """
        assert self.bip32, "BIP32 not initialized yet."
        # integer keyset id modulo max number of bip32 child keys
        try:
            keyest_id_int = int.from_bytes(bytes.fromhex(self.keyset_id), "big") % (
                2**31 - 1
            )
        except ValueError:
            # BEGIN: BACKWARDS COMPATIBILITY < 0.15.0 keyset id is not hex
            # calculate an integer keyset id from the base64 encoded keyset id
            keyest_id_int = int.from_bytes(base64.b64decode(self.keyset_id), "big") % (
                2**31 - 1
            )
            # END: BACKWARDS COMPATIBILITY < 0.15.0 keyset id is not hex

        logger.trace(f"keyset id: {self.keyset_id} becomes {keyest_id_int}")
        token_derivation_path = f"m/129372'/0'/{keyest_id_int}'/{counter}'"
        # for secret
        secret_derivation_path = f"{token_derivation_path}/0"
        logger.trace(f"secret derivation path: {secret_derivation_path}")
        secret = self.bip32.get_privkey_from_path(secret_derivation_path)
        # blinding factor
        r_derivation_path = f"{token_derivation_path}/1"
        logger.trace(f"r derivation path: {r_derivation_path}")
        r = self.bip32.get_privkey_from_path(r_derivation_path)
        return secret, r, token_derivation_path

    async def generate_n_secrets(
        self, n: int = 1, skip_bump: bool = False
    ) -> Tuple[List[str], List[PrivateKey], List[str]]:
        """Generates n secrets and blinding factors and returns a tuple of secrets,
        blinding factors, and derivation paths.

        Args:
            n (int, optional): Number of secrets to generate. Defaults to 1.
            skip_bump (bool, optional): Skip increment of secret counter in the database.
            You want to set this to false if you don't know whether the following operation
            will succeed or not (like a POST /mint request). Defaults to False.

        Returns:
            Tuple[List[str], List[PrivateKey], List[str]]: Secrets, blinding factors, derivation paths

        """
        if n < 1:
            return [], [], []

        secret_counters_start = await bump_secret_derivation(
            db=self.db, keyset_id=self.keyset_id, by=n, skip=skip_bump
        )
        logger.trace(f"secret_counters_start: {secret_counters_start}")
        secret_counters = list(range(secret_counters_start, secret_counters_start + n))
        logger.trace(
            f"Generating secret nr {secret_counters[0]} to {secret_counters[-1]}."
        )
        secrets_rs_derivationpaths = [
            await self.generate_determinstic_secret(s) for s in secret_counters
        ]
        # secrets are supplied as str
        secrets = [s[0].hex() for s in secrets_rs_derivationpaths]
        # rs are supplied as PrivateKey
        rs = [PrivateKey(privkey=s[1], raw=True) for s in secrets_rs_derivationpaths]

        derivation_paths = [s[2] for s in secrets_rs_derivationpaths]

        return secrets, rs, derivation_paths

    async def generate_secrets_from_to(
        self, from_counter: int, to_counter: int
    ) -> Tuple[List[str], List[PrivateKey], List[str]]:
        """Generates secrets and blinding factors from `from_counter` to `to_counter`

        Args:
            from_counter (int): Start counter
            to_counter (int): End counter

        Returns:
            Tuple[List[str], List[PrivateKey], List[str]]: Secrets, blinding factors, derivation paths

        Raises:
            ValueError: If `from_counter` is larger than `to_counter`
        """
        assert (
            from_counter <= to_counter
        ), "from_counter must be smaller than to_counter"
        secret_counters = [c for c in range(from_counter, to_counter + 1)]
        secrets_rs_derivationpaths = [
            await self.generate_determinstic_secret(s) for s in secret_counters
        ]
        # secrets are supplied as str
        secrets = [s[0].hex() for s in secrets_rs_derivationpaths]
        # rs are supplied as PrivateKey
        rs = [PrivateKey(privkey=s[1], raw=True) for s in secrets_rs_derivationpaths]
        derivation_paths = [s[2] for s in secrets_rs_derivationpaths]
        return secrets, rs, derivation_paths
