import base64
from typing import Dict, List, Optional

from loguru import logger

from ..core.base import MintKeyset, Unit
from ..core.crypto.keys import derive_keyset_id
from ..core.errors import KeysetError, KeysetNotFoundError
from ..core.settings import settings
from .protocols import SupportsDb, SupportsKeysets, SupportsSeed


class LedgerKeysets(SupportsKeysets, SupportsSeed, SupportsDb):
    
    # ------- KEYS -------

    def maybe_update_derivation_path(self):
        """
        Check whether `self.derivation_path` was superseded by any of the active keysets loaded into this instance
        upon initialization. The superseding derivation must have a greater count (last portion of the derivation path).
        If this condition is true, update `self.derivation_path` to match the highest count derivation.
        """
        derivation: List[str] = self.derivation_path.split("/") # type: ignore
        counter = int(derivation[-1].replace("'", ""))
        for keyset in self.keysets.values():
            if keyset.active:
                keyset_derivation_path = keyset.derivation_path.split("/")
                keyset_derivation_counter = int(keyset_derivation_path[-1].replace("'", ""))
                if (
                    keyset_derivation_path[:-1] == derivation[:-1]
                    and keyset_derivation_counter > counter
                ):
                    self.derivation_path = keyset.derivation_path

    async def rotate_next_keyset(
        self,
        unit: Unit,
        max_order: Optional[int],
        input_fee_ppk: Optional[int]
    ) -> MintKeyset:
        """
        This function:
            1. finds the highest counter keyset for `unit`
            2. creates a new derivation path from the old one, increasing the counter by one
            3. creates a new active keyset for the new derivation path
            4. de-activates the old keyset
            5. stores the new keyset to DB
        
        Args:
            unit (Unit): Unit of the keyset.
            max_order (Optional[int], optional): The number of keys to generate, which correspond to powers of 2.
            input_fee_ppk (Optional[int], optional):  The new keyset's fee
        Returns:
            MintKeyset: Resulting keyset of the rotation
        """

        logger.info(f"Attempting keyset rotation for unit {str(Unit)}")

        # Select keyset with the greatest counter
        selected_keyset = None
        selected_keyset_counter = -1
        for keyset in self.keysets.values():
            if keyset.active and keyset.unit == unit:
                keyset_derivation_path = keyset.derivation_path.split("/")
                keyset_derivation_counter = int(keyset_derivation_path[-1].replace("'", ""))
                if keyset_derivation_counter > selected_keyset_counter:
                    selected_keyset = keyset

        # If no selected keyset, then there is no keyset for this unit
        if not selected_keyset:
            logger.error(f"Couldn't find suitable keyset for rotation with unit {str(unit)}")
            raise Exception(f"Couldn't find suitable keyset for rotation with unit {str(unit)}")

        logger.info(f"Rotating keyset {selected_keyset.id}")

        # New derivation path is just old derivation path with increased counter
        new_derivation_path = selected_keyset.derivation_path.split("/")
        new_derivation_path[-1] = str(int(new_derivation_path[-1].replace("'", "")) + 1) + "'"
        
        # keys amounts for this keyset: if amounts is None we use `self.amounts`
        amounts = [2**i for i in range(max_order)] if max_order else self.amounts

        # Generate the keyset
        new_keyset = MintKeyset(
            derivation_path="/".join(new_derivation_path),
            seed=self.seed,
            amounts=amounts,
        )

        logger.debug(f"New keyset was generated with Id {new_keyset.id}. Saving...")
        await self.crud.store_keyset(keyset=new_keyset, db=self.db)

        logger.debug(f"De-activating keyset {keyset.id}...")
        keyset.active = False
        await self.crud.update_keyset(keyset=keyset, db=self.db)

        return new_keyset

    async def activate_keyset(
        self,
        *,
        derivation_path: str,
        seed: Optional[str] = None,
        version: Optional[str] = None,
        autosave=True,
    ) -> MintKeyset:
        """
        Load an existing keyset for the specified derivation path or generate a new one if it doesn't exist.
        Optionally store the newly created keyset in the database.

        Args:
            derivation_path (str): Derivation path for keyset generation.
            seed (Optional[str], optional): Seed value. Defaults to None.
            version (Optional[str], optional): Version identifier. Defaults to None.
            autosave (bool, optional): Whether to store the keyset if newly created. Defaults to True.

        Returns:
            MintKeyset: The activated keyset.
        """
        if not derivation_path:
            raise ValueError("Derivation path must be provided.")

        seed = seed or self.seed
        version = version or settings.version
        # Initialize a temporary keyset to derive the ID
        temp_keyset = MintKeyset(
            seed=seed,
            derivation_path=derivation_path,
            version=version,
            amounts=self.amounts,
        )
        logger.debug(
            f"Activating keyset for derivation path '{derivation_path}' with ID '{temp_keyset.id}'."
        )

        # Attempt to retrieve existing keysets from the database
        existing_keysets: List[MintKeyset] = await self.crud.get_keyset(
            id=temp_keyset.id, db=self.db
        )
        logger.trace(
            f"Retrieved {len(existing_keysets)} keyset(s) for derivation path '{derivation_path}'."
        )

        if existing_keysets:
            keyset = existing_keysets[0]
        else:
            # Create a new keyset if none exists
            keyset = MintKeyset(
                seed=seed,
                derivation_path=derivation_path,
                amounts=self.amounts,
                version=version,
                input_fee_ppk=settings.mint_input_fee_ppk,
            )
            logger.debug(f"Generated new keyset with ID '{keyset.id}'.")

            if autosave:
                logger.debug(f"Storing new keyset with ID '{keyset.id}'.")
                await self.crud.store_keyset(keyset=keyset, db=self.db)

        # Activate the keyset
        keyset.active = True
        self.keysets[keyset.id] = keyset
        logger.debug(f"Keyset with ID '{keyset.id}' is now active.")

        return keyset

    async def init_keysets(self, autosave: bool = True) -> None:
        """Initializes all keysets of the mint from the db. Loads all past keysets from db
        and generate their keys. Then activate the current keyset set by self.derivation_path.

        Args:
            autosave (bool, optional): Whether the current keyset should be saved if it is
                not in the database yet. Will be passed to `self.activate_keyset` where it is
                generated from `self.derivation_path`. Defaults to True.
        """
        # load all past keysets from db, the keys will be generated at instantiation
        tmp_keysets: List[MintKeyset] = await self.crud.get_keyset(db=self.db)

        # add keysets from db to memory
        for k in tmp_keysets:
            self.keysets[k.id] = k

        logger.info(f"Loaded {len(self.keysets)} keysets from database.")

        # Check if any of the loaded keysets marked as active
        # do supersede the one specified in the derivation settings.
        # If this is the case update to latest count derivation.
        self.maybe_update_derivation_path()

        # activate the current keyset set by self.derivation_path
        # and self.derivation_path is not superseded by any other
        # active keyset with same derivation path but higher count
        if self.derivation_path:
            self.keyset = await self.activate_keyset(
                derivation_path=self.derivation_path, autosave=autosave
            )
            logger.info(f"Current keyset: {self.keyset.id}")

        # check that we have a least one active keyset
        if not any([k.active for k in self.keysets.values()]):
            raise KeysetError("No active keyset found.")

        # DEPRECATION 0.16.1 – disable base64 keysets if hex equivalent exists
        if settings.mint_inactivate_base64_keysets:
            await self.inactivate_base64_keysets()

    async def inactivate_base64_keysets(self) -> None:
        """Inactivates all base64 keysets that have a hex equivalent."""
        for keyset in self.keysets.values():
            if not keyset.active or not keyset.public_keys:
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
                if hex_keyset_id not in [k.id for k in self.keysets.values()]:
                    logger.warning(
                        f"Keyset {keyset.id} is base64 but we don't have a hex version. Ignoring."
                    )
                    continue

                logger.warning(
                    f"Keyset {keyset.id} is base64 and has a hex counterpart, setting inactive."
                )
                keyset.active = False
                self.keysets[keyset.id] = keyset
                await self.crud.update_keyset(keyset=keyset, db=self.db)

    def get_keyset(self, keyset_id: Optional[str] = None) -> Dict[int, str]:
        """Returns a dictionary of hex public keys of a specific keyset for each supported amount"""
        if keyset_id and keyset_id not in self.keysets:
            raise KeysetNotFoundError()
        keyset = self.keysets[keyset_id] if keyset_id else self.keyset
        if not keyset.public_keys:
            raise KeysetError("no public keys for this keyset")
        return {a: p.serialize().hex() for a, p in keyset.public_keys.items()}