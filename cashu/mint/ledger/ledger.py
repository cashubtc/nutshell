import asyncio
from typing import Dict, List, Mapping, Optional

from loguru import logger

from ...core.base import (
    Method,
    MintKeyset,
    Unit,
)
from ...core.crypto.aes import AESCipher
from ...core.crypto.keys import derive_pubkey
from ...core.crypto.secp import PublicKey
from ...core.db import Database
from ...core.settings import settings
from ...lightning.base import LightningBackend
from ..crud import LedgerCrudSqlite
from ..db.read import DbReadHelper
from ..db.write import DbWriteHelper
from ..events.events import LedgerEventManager
from ..features import LedgerFeatures
from ..keysets import LedgerKeysets
from ..tasks import LedgerTasks
from ..watchdog import LedgerWatchdog
from .melt import LedgerMelt
from .mint import LedgerMint
from .swap import LedgerSwap


class Ledger(
    LedgerMint,  # provides LedgerWatchdog via inheritance
    LedgerMelt,
    LedgerSwap,
    LedgerTasks,
    LedgerFeatures,
    LedgerKeysets,
):
    backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
    keysets: Dict[str, MintKeyset] = {}
    events = LedgerEventManager()
    db: Database
    db_read: DbReadHelper
    db_write: DbWriteHelper
    invoice_listener_tasks: List[asyncio.Task] = []
    watchdog_tasks: List[asyncio.Task] = []
    disable_melt: bool = False
    pubkey: PublicKey

    def __init__(
        self,
        *,
        db: Database,
        seed: str,
        derivation_path="",
        amounts: Optional[List[int]] = None,
        backends: Optional[Mapping[Method, Mapping[Unit, LightningBackend]]] = None,
        seed_decryption_key: Optional[str] = None,
        crud=LedgerCrudSqlite(),
    ) -> None:
        self.keysets: Dict[str, MintKeyset] = {}
        self.backends: Mapping[Method, Mapping[Unit, LightningBackend]] = {}
        self.events = LedgerEventManager()
        self.db_read: DbReadHelper
        self.locks: Dict[str, asyncio.Lock] = {}  # holds multiprocessing locks
        self.invoice_listener_tasks: List[asyncio.Task] = []
        self.watchdog_tasks: List[asyncio.Task] = []
        self.regular_tasks: List[asyncio.Task] = []

        if not seed:
            raise Exception("seed not set")

        # decrypt seed if seed_decryption_key is set
        try:
            self.seed = (
                AESCipher(seed_decryption_key).decrypt(seed)
                if seed_decryption_key
                else seed
            )
        except Exception as e:
            raise Exception(
                f"Could not decrypt seed. Make sure that the seed is correct and the decryption key is set. {e}"
            )
        self.derivation_path = derivation_path

        self.db = db
        self.crud = crud

        if backends:
            self.backends = backends

        if amounts:
            self.amounts = amounts
        else:
            self.amounts = [2**n for n in range(settings.max_order)]

        self.pubkey = derive_pubkey(self.seed)
        self.db_read = DbReadHelper(self.db, self.crud)
        self.db_write = DbWriteHelper(self.db, self.crud, self.events, self.db_read)

        LedgerWatchdog.__init__(self)

    # ------- STARTUP -------

    async def startup_ledger(self) -> None:
        await self._startup_keysets()
        await self._check_backends()
        self.regular_tasks.append(asyncio.create_task(self._run_regular_tasks()))
        self.invoice_listener_tasks = await self.dispatch_listeners()
        if settings.mint_watchdog_enabled:
            self.watchdog_tasks = await self.dispatch_watchdogs()

    async def _startup_keysets(self) -> None:
        await self.init_keysets()
        for derivation_path in settings.mint_derivation_path_list:
            derivation_path = self.maybe_update_derivation_path(derivation_path)
            await self.activate_keyset(derivation_path=derivation_path)

    async def _run_regular_tasks(self) -> None:
        """
        Runs periodic ledger maintenance tasks forever.
        This function intentionally loops forever and is designed to be scheduled as a Task.
        """
        logger.info("Starting ledger regular tasks loop")
        while True:
            try:
                await self._check_pending_proofs_and_melt_quotes()
                await asyncio.sleep(settings.mint_regular_tasks_interval_seconds)
            except Exception as e:
                logger.error(f"Ledger regular task failed: {e}")
                await asyncio.sleep(60)

    async def _check_backends(self) -> None:
        for method in self.backends:
            for unit in self.backends[method]:
                logger.info(
                    f"Using {self.backends[method][unit].__class__.__name__} backend for"
                    f" method: '{method.name}' and unit: '{unit.name}'"
                )
                status = await self.backends[method][unit].status()
                if status.error_message:
                    logger.error(
                        "The backend for"
                        f" {self.backends[method][unit].__class__.__name__} isn't"
                        f" working properly: '{status.error_message}'"
                    )
                    exit(1)
                logger.info(f"Backend balance: {status.balance}")

        logger.info(f"Data dir: {settings.cashu_dir}")

    async def shutdown_ledger(self) -> None:
        logger.debug("Shutting down invoice listeners")
        for task in self.invoice_listener_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        for task in self.watchdog_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.debug("Shutting down regular tasks")
        for task in self.regular_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        logger.debug("Disconnecting from database")
        await self.db.engine.dispose()

    async def _check_pending_proofs_and_melt_quotes(self):
        """Startup routine that checks all pending melt quotes and either invalidates
        their pending proofs for a successful melt or deletes them if the melt failed.
        """
        # get all pending melt quotes
        pending_melt_quotes = await self.crud.get_all_melt_quotes_from_pending_proofs(
            db=self.db
        )
        if not pending_melt_quotes:
            return
        logger.info(f"Checking {len(pending_melt_quotes)} pending melt quotes")
        for quote in pending_melt_quotes:
            quote = await self.get_melt_quote(quote_id=quote.quote)
            logger.info(f"Melt quote {quote.quote} state: {quote.state}")
