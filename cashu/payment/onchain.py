from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any, Optional

import bdkpython as bdk
from pydantic import BaseModel, ConfigDict, Field

from ..core.base import Amount, MeltQuote, MintQuote, Unit
from ..core.models import PostMeltQuoteRequest, PostMintQuoteRequest
from ..lightning.base import (
    InvoiceResponse,
    PaymentQuoteResponse,
    PaymentResponse,
    PaymentResult,
    PaymentStatus,
    StatusResponse,
)
from .base import PaymentMethodPlugin, PaymentMethodSettings


class OnchainMintQuoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    unit: str
    pubkey: str
    amount: int = Field(default=0, exclude=True)
    description: None = Field(default=None, exclude=True)


class OnchainMeltQuoteRequest(PostMeltQuoteRequest):
    model_config = ConfigDict(extra="forbid")

    amount: int = Field(gt=0)


class BdkOnchainBackend:
    """Persistent BIP84 BDK wallet synchronized through Bitcoin Core RPC."""

    def __init__(self, unit: Unit, config: dict[str, Any]) -> None:
        if unit != Unit.sat:
            raise ValueError("the onchain backend currently supports only sat")
        self.unit = unit
        self.confirmations = int(config.get("confirmations", 1))
        self.min_amount = int(config.get("min_amount", 1))
        self.fee_target = int(config.get("fee_target", 1))
        self.fallback_fee_rate = float(config.get("fallback_fee_rate", 2))
        self.quote_max_input_count = int(config.get("quote_max_input_count", 10))
        wallet_name = str(config.get("wallet", "nutshell-onchain"))

        mnemonic = config.get("mnemonic")
        mnemonic_file = config.get("mnemonic_file")
        if mnemonic_file:
            mnemonic = Path(str(mnemonic_file)).read_text().strip()
        if not mnemonic:
            raise ValueError("onchain backend requires mnemonic or mnemonic_file")

        database_path = Path(
            str(config.get("database_path", f"./data/{wallet_name}.sqlite"))
        )
        database_path.parent.mkdir(parents=True, exist_ok=True)
        secret = bdk.DescriptorSecretKey(
            bdk.Network.REGTEST, bdk.Mnemonic.from_string(str(mnemonic)), None
        )
        external = bdk.Descriptor.new_bip84(
            secret, bdk.KeychainKind.EXTERNAL, bdk.Network.REGTEST
        )
        internal = bdk.Descriptor.new_bip84(
            secret, bdk.KeychainKind.INTERNAL, bdk.Network.REGTEST
        )
        self._wallet = bdk.Wallet(
            external,
            internal,
            bdk.Network.REGTEST,
            bdk.DatabaseConfig.SQLITE(
                bdk.SqliteDbConfiguration(path=str(database_path))
            ),
        )
        self._blockchain = bdk.Blockchain(
            bdk.BlockchainConfig.RPC(
                bdk.RpcConfig(
                    url=str(config.get("rpc_url", "http://127.0.0.1:18443")),
                    auth=bdk.Auth.USER_PASS(
                        str(config.get("rpc_user", "cashu")),
                        str(config.get("rpc_password", "cashu")),
                    ),
                    network=bdk.Network.REGTEST,
                    wallet_name=wallet_name,
                    sync_params=bdk.RpcSyncParams(
                        start_script_count=int(config.get("start_script_count", 100)),
                        start_time=int(config.get("start_time", 0)),
                        force_start_time=False,
                        poll_rate_sec=1,
                    ),
                )
            )
        )
        self._lock = asyncio.Lock()

    def _sync(self) -> None:
        self._wallet.sync(self._blockchain, None)

    @staticmethod
    def _is_confirmed(
        transaction: bdk.TransactionDetails, height: int, confirmations: int
    ) -> bool:
        block = transaction.confirmation_time
        return block is not None and height - block.height + 1 >= confirmations

    async def status(self) -> StatusResponse:
        try:
            async with self._lock:
                await asyncio.to_thread(self._sync)
                balance = await asyncio.to_thread(self._wallet.get_balance)
            return StatusResponse(balance=Amount(Unit.sat, balance.total))
        except Exception as exc:
            return StatusResponse(balance=Amount(Unit.sat, 0), error_message=str(exc))

    async def new_address(self) -> str:
        async with self._lock:
            info = await asyncio.to_thread(
                self._wallet.get_address, bdk.AddressIndex.NEW()
            )
        return info.address.as_string()

    async def received(self, address: str) -> int:
        target = bdk.Address(address, bdk.Network.REGTEST).script_pubkey().to_bytes()
        async with self._lock:
            await asyncio.to_thread(self._sync)
            height = await asyncio.to_thread(self._blockchain.get_height)
            transactions = await asyncio.to_thread(self._wallet.list_transactions, True)
        return sum(
            output.value
            for details in transactions
            if self._is_confirmed(details, height, self.confirmations)
            and details.transaction
            for output in details.transaction.output()
            if output.script_pubkey.to_bytes() == target
            and output.value >= self.min_amount
        )

    async def fee_quote(
        self, address: str, amount: int
    ) -> tuple[int, list[dict[str, int]]]:
        bdk.Address(address, bdk.Network.REGTEST)
        try:
            sat_vb = (
                await asyncio.to_thread(self._blockchain.estimate_fee, self.fee_target)
            ).as_sat_per_vb()
        except Exception:
            sat_vb = self.fallback_fee_rate
        # Conservative P2WPKH weight bound: version/locktime/varints, configured
        # maximum inputs, destination, and change. This mirrors CDK's bounded
        # input-count approach and keeps the fixed NUT-30 quote from underfunding.
        estimated_vbytes = 72 + 68 * self.quote_max_input_count
        reserve = max(1, int(sat_vb * estimated_vbytes + 0.999999))
        return reserve, [
            {
                "fee_index": 0,
                "fee_reserve": reserve,
                "estimated_blocks": self.fee_target,
            }
        ]

    async def send(self, address: str, amount: int) -> tuple[str, int, str]:
        destination = bdk.Address(address, bdk.Network.REGTEST).script_pubkey()
        async with self._lock:
            await asyncio.to_thread(self._sync)
            try:
                sat_vb = (
                    await asyncio.to_thread(
                        self._blockchain.estimate_fee, self.fee_target
                    )
                ).as_sat_per_vb()
            except Exception:
                sat_vb = self.fallback_fee_rate
            result = await asyncio.to_thread(
                bdk.TxBuilder()
                .add_recipient(destination, amount)
                .fee_rate(sat_vb)
                .finish,
                self._wallet,
            )
            finalized = await asyncio.to_thread(self._wallet.sign, result.psbt, None)
            if not finalized:
                raise RuntimeError("BDK could not finalize onchain transaction")
            transaction = result.psbt.extract_tx()
            await asyncio.to_thread(self._blockchain.broadcast, transaction)
        txid = transaction.txid()
        vout = next(
            i
            for i, output in enumerate(transaction.output())
            if output.script_pubkey.to_bytes() == destination.to_bytes()
        )
        return txid, result.transaction_details.fee or 0, f"{txid}:{vout}"

    async def transaction_status(self, txid: str) -> PaymentStatus:
        async with self._lock:
            await asyncio.to_thread(self._sync)
            height = await asyncio.to_thread(self._blockchain.get_height)
            transactions = await asyncio.to_thread(self._wallet.list_transactions, True)
        details = next((tx for tx in transactions if tx.txid == txid), None)
        if details is None:
            return PaymentStatus(result=PaymentResult.UNKNOWN)
        outpoint = txid
        if details.transaction:
            external = [
                i
                for i, output in enumerate(details.transaction.output())
                if not self._wallet.is_mine(output.script_pubkey)
            ]
            if external:
                outpoint = f"{txid}:{external[0]}"
        return PaymentStatus(
            result=(
                PaymentResult.SETTLED
                if self._is_confirmed(details, height, self.confirmations)
                else PaymentResult.PENDING
            ),
            fee=Amount(Unit.sat, details.fee or 0),
            preimage=outpoint,
        )


class OnchainPaymentMethod(PaymentMethodPlugin):
    method = "onchain"
    mint_quote_request_model = OnchainMintQuoteRequest
    melt_quote_request_model = OnchainMeltQuoteRequest
    allows_partial_mint = True
    supports_mint_quote_expiry = False

    def create_backend(self, unit: Unit, config: dict[str, Any]) -> BdkOnchainBackend:
        return BdkOnchainBackend(unit, config)

    def settings_for(
        self, backend: BdkOnchainBackend, unit: Unit
    ) -> PaymentMethodSettings:
        return PaymentMethodSettings(
            method_name=self.method,
            min_amount=backend.min_amount,
            options={"confirmations": backend.confirmations},
        )

    async def create_incoming_payment(
        self, backend: BdkOnchainBackend, request: PostMintQuoteRequest
    ) -> InvoiceResponse:
        address = await backend.new_address()
        return InvoiceResponse(ok=True, checking_id=address, payment_request=address)

    async def get_incoming_payment_status(
        self, backend: BdkOnchainBackend, quote: MintQuote
    ) -> PaymentStatus:
        paid = await backend.received(quote.checking_id)
        return PaymentStatus(
            result=PaymentResult.SETTLED if paid > 0 else PaymentResult.PENDING,
            amount_paid=Amount(Unit.sat, paid),
        )

    async def quote_outgoing_payment(
        self, backend: BdkOnchainBackend, request: PostMeltQuoteRequest
    ) -> PaymentQuoteResponse:
        amount = int(getattr(request, "amount"))
        reserve, options = await backend.fee_quote(request.request, amount)
        return PaymentQuoteResponse.model_validate(
            {
                "checking_id": request.request,
                "amount": Amount(Unit.sat, amount),
                "fee": Amount(Unit.sat, reserve),
                "fee_options": options,
                "selected_fee_index": None,
                "outpoint": None,
            }
        )

    async def execute_outgoing_payment(
        self, backend: BdkOnchainBackend, quote: MeltQuote, fee_limit: Amount
    ) -> PaymentResponse:
        txid, fee, outpoint = await backend.send(quote.request, quote.amount)
        return PaymentResponse(
            result=PaymentResult.PENDING,
            checking_id=txid,
            # The selected reserve is the maximum fee chargeable to the user.
            fee=Amount(Unit.sat, min(fee, fee_limit.amount)),
            preimage=outpoint,
        )

    async def get_outgoing_payment_status(
        self, backend: BdkOnchainBackend, quote: MeltQuote
    ) -> PaymentStatus:
        status = await backend.transaction_status(quote.checking_id)
        if status.fee and status.fee.amount > quote.fee_reserve:
            status.fee = Amount(Unit.sat, quote.fee_reserve)
        return status

    def quote_expiry(self, payment_request: str) -> Optional[int]:
        return None

    def mint_quote_expiry(self, payment_request: str) -> Optional[int]:
        # An unbounded reusable address avoids accepting deposits first seen
        # after an expiry, which would violate NUT-30.
        return None

    def melt_quote_expiry(self, payment_request: str) -> Optional[int]:
        return int(time.time()) + 600

    def validate_internal_settlement(
        self, mint_quote: MintQuote, melt_quote: MeltQuote
    ) -> None:
        if mint_quote.request != melt_quote.request:
            raise ValueError("payment requests do not match")


onchain_payment_method = OnchainPaymentMethod()

# Compatibility for early users of this branch.
BitcoinCoreRpcBackend = BdkOnchainBackend
