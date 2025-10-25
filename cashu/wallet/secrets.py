import base64
import hashlib
import hmac
import os
from typing import List, Optional, Tuple

from bip32 import BIP32
from loguru import logger
from mnemonic import Mnemonic

from ..core.crypto.keys import get_keyset_id_version
from ..core.crypto.secp import PrivateKey
from ..core.db import Database
from ..core.secret import Secret
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

    async def _generate_random_secret(self) -> str:
        """Returns base64 encoded deterministic random string.

        NOTE: This method should probably retire after `deterministic_secrets`. We are
        deriving secrets from a counter but don't store the respective blinding factor.
        We won't be able to restore any ecash generated with these secrets.
        """
        # return random 32 byte hex string
        return hashlib.sha256(os.urandom(32)).hexdigest()

    async def generate_determinstic_secret(
        self, counter: int, keyset_id: Optional[str] = None
    ) -> Tuple[bytes, bytes, str]:
        """
        Determinstically generates two secrets (one as the secret message,
        one as the blinding factor) using versioned derivation.
        
        NUT-13: Uses keyset version to determine derivation method:
        - Version "base64" (ancient, pre-0.15.0): BIP32 derivation
        - Version "00" (legacy): BIP32 derivation 
        - Version "01" (v2): HMAC-SHA256 derivation
        """
        keyset_id = keyset_id or self.keyset_id
        
        # Get keyset version to determine derivation method
        version = get_keyset_id_version(keyset_id)
        logger.trace(f"Keyset {keyset_id} version: {version}")
        
        if version == "base64" or version == "00":
            # BIP32 derivation for base64 (ancient) and version 00 keysets
            return await self._derive_secret_bip32(counter, keyset_id)
        elif version == "01":
            # HMAC-SHA256 derivation for version 01 keysets (per NUT-13 test vectors)
            return await self._derive_secret_hmac_sha256(counter, keyset_id)
        else:
            raise ValueError(f"Unsupported keyset version: {version}")

    async def _derive_secret_bip32(
        self, counter: int, keyset_id: str
    ) -> Tuple[bytes, bytes, str]:
        """
        Derives secret and blinding factor using BIP32 derivation (legacy method).
        Used for keyset version "00".
        """
        assert self.bip32, "BIP32 not initialized yet."
        
        # integer keyset id modulo max number of bip32 child keys
        try:
            keyest_id_int = int.from_bytes(bytes.fromhex(keyset_id), "big") % (
                2**31 - 1
            )
        except ValueError:
            # BEGIN: BACKWARDS COMPATIBILITY < 0.15.0 keyset id is not hex
            # calculate an integer keyset id from the base64 encoded keyset id
            keyest_id_int = int.from_bytes(base64.b64decode(keyset_id), "big") % (
                2**31 - 1
            )
            # END: BACKWARDS COMPATIBILITY < 0.15.0 keyset id is not hex

        logger.trace(f"BIP32: keyset id: {keyset_id} becomes {keyest_id_int}")
        token_derivation_path = f"m/129372'/0'/{keyest_id_int}'/{counter}'"
        # for secret
        secret_derivation_path = f"{token_derivation_path}/0"
        logger.trace(f"BIP32: secret derivation path: {secret_derivation_path}")
        secret = self.bip32.get_privkey_from_path(secret_derivation_path)
        # blinding factor
        r_derivation_path = f"{token_derivation_path}/1"
        logger.trace(f"BIP32: r derivation path: {r_derivation_path}")
        r = self.bip32.get_privkey_from_path(r_derivation_path)
        return secret, r, token_derivation_path

    async def _derive_secret_hmac_sha256(
        self, counter: int, keyset_id: str
    ) -> Tuple[bytes, bytes, str]:
        """
        Derives secret and blinding factor using HMAC-SHA256 derivation for keyset version "01".
        NUT-13 (updated):
        - message = b"Cashu_KDF_HMAC_SHA256" || keyset_id_bytes || counter_bytes
        - secret  = HMAC_SHA256(seed, message || 0x00)
        - r       = HMAC_SHA256(seed, message || 0x01)
        - counter_bytes is 8-byte unsigned big-endian
        """
        assert self.seed, "Seed not initialized yet."
        keyset_id_bytes = bytes.fromhex(keyset_id)
        counter_bytes = counter.to_bytes(8, byteorder="big", signed=False)
        base = b"Cashu_KDF_HMAC_SHA256" + keyset_id_bytes + counter_bytes
        secret = hmac.new(self.seed, base + b"\x00", hashlib.sha256).digest()
        r = hmac.new(self.seed, base + b"\x01", hashlib.sha256).digest()
        derivation_path = f"HMAC-SHA256:{keyset_id}:{counter}"
        return secret, r, derivation_path

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
        async with self.db.get_connection(lock_table="keysets") as conn:
            secret_counters_start = await bump_secret_derivation(
                db=self.db, keyset_id=self.keyset_id, by=n, skip=skip_bump, conn=conn
            )
            logger.trace(f"secret_counters_start: {secret_counters_start}")
            secret_counters = list(
                range(secret_counters_start, secret_counters_start + n)
            )
            logger.trace(
                f"Generating secret nr {secret_counters[0]} to {secret_counters[-1]}."
            )
            secrets_rs_derivationpaths = [
                await self.generate_determinstic_secret(s) for s in secret_counters
            ]
            # secrets are supplied as str
            secrets = [s[0].hex() for s in secrets_rs_derivationpaths]
            # rs are supplied as PrivateKey
            rs = [
                PrivateKey(privkey=s[1], raw=True) for s in secrets_rs_derivationpaths
            ]

            derivation_paths = [s[2] for s in secrets_rs_derivationpaths]

            return secrets, rs, derivation_paths

    async def generate_secrets_from_to(
        self, from_counter: int, to_counter: int, keyset_id: Optional[str] = None
    ) -> Tuple[List[str], List[PrivateKey], List[str]]:
        """Generates secrets and blinding factors from `from_counter` to `to_counter`

        Args:
            from_counter (int): Start counter
            to_counter (int): End counter
            keyset_id (Optional[str], optional): Keyset id. Defaults to None.

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
            await self.generate_determinstic_secret(s, keyset_id)
            for s in secret_counters
        ]
        # secrets are supplied as str
        secrets = [s[0].hex() for s in secrets_rs_derivationpaths]
        # rs are supplied as PrivateKey
        rs = [PrivateKey(privkey=s[1], raw=True) for s in secrets_rs_derivationpaths]
        derivation_paths = [s[2] for s in secrets_rs_derivationpaths]
        return secrets, rs, derivation_paths

    async def generate_locked_secrets(
        self, send_outputs: List[int], keep_outputs: List[int], secret_lock: Secret
    ) -> Tuple[List[str], List[PrivateKey], List[str]]:
        """Generates secrets and blinding factors for a transaction with `send_outputs` and `keep_outputs`.

        Args:
            send_outputs (List[int]): List of amounts to send
            keep_outputs (List[int]): List of amounts to keep

        Returns:
            Tuple[List[str], List[PrivateKey], List[str]]: Secrets, blinding factors, derivation paths
        """
        rs: List[PrivateKey] = []
        # generate secrets for receiver
        secret_locks = [secret_lock.serialize() for i in range(len(send_outputs))]
        logger.debug(f"Creating proofs with custom secrets: {secret_locks}")
        # append predefined secrets (to send) to random secrets (to keep)
        # generate secrets to keep
        secrets = [
            await self._generate_random_secret() for s in range(len(keep_outputs))
        ] + secret_locks
        # TODO: derive derivation paths from secrets
        derivation_paths = ["custom"] * len(secrets)

        return secrets, rs, derivation_paths
