from __future__ import annotations

import datetime
import hashlib
import pickle
import random
import time
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from .ledger import Ledger

import httpx
from coincurve import PrivateKey
from loguru import logger

from ..core.base import PolReceipt
from ..core.crypto.b_dhke import hash_to_curve
from ..core.settings import settings
from .cache import RedisCache

redis = RedisCache()

Node = Tuple[bytes, int]

_FALLBACK_MEM_CACHE: Dict[
    str, Tuple["MerkleMountainRangeSum", "MerkleMountainRangeSum"]
] = {}


def _parent(left: Node, right: Node) -> Node:
    parent_sum = left[1] + right[1]
    if parent_sum >= 2**64:
        raise OverflowError("sum-MMR node sum exceeds uint64")
    parent_hash = hashlib.sha256(
        left[0] + right[0] + left[1].to_bytes(8, "big") + right[1].to_bytes(8, "big")
    ).digest()
    return parent_hash, parent_sum


class MerkleMountainRangeSum:
    """Append-only Merkle Mountain Range with uint64 sums."""

    def __init__(self, leaves: List[Node]):
        if any(len(leaf_hash) != 32 for leaf_hash, _ in leaves):
            raise ValueError("sum-MMR leaf hashes must be 32 bytes")
        if any(value < 0 or value >= 2**64 for _, value in leaves):
            raise OverflowError("sum-MMR leaf sum is outside uint64")
        self.leaves = leaves
        self._mountains: List[Tuple[int, List[List[Node]]]] = []
        offset = 0
        remaining = len(leaves)
        while remaining:
            height = remaining.bit_length() - 1
            width = 1 << height
            levels = [leaves[offset : offset + width]]
            while len(levels[-1]) > 1:
                current = levels[-1]
                levels.append(
                    [
                        _parent(current[i], current[i + 1])
                        for i in range(0, len(current), 2)
                    ]
                )
            self._mountains.append((offset, levels))
            offset += width
            remaining -= width

    @property
    def size(self) -> int:
        return len(self.leaves)

    @property
    def peaks(self) -> List[Node]:
        return [levels[-1][0] for _, levels in self._mountains]

    @property
    def root(self) -> Node:
        if not self._mountains:
            return hashlib.sha256(b"").digest(), 0
        bagged = self.peaks[-1]
        for peak in reversed(self.peaks[:-1]):
            bagged = _parent(peak, bagged)
        return bagged

    def find_leaf(self, leaf_hash: bytes) -> Optional[int]:
        return next(
            (index for index, leaf in enumerate(self.leaves) if leaf[0] == leaf_hash),
            None,
        )

    def get_proof(self, leaf_index: int) -> Tuple[List[Dict], List[Dict]]:
        if leaf_index < 0 or leaf_index >= self.size:
            raise IndexError("sum-MMR leaf index out of range")

        sibling_path: List[Dict] = []
        for offset, levels in self._mountains:
            width = len(levels[0])
            if not offset <= leaf_index < offset + width:
                continue
            local_index = leaf_index - offset
            for level in levels[:-1]:
                sibling_index = local_index ^ 1
                sibling = level[sibling_index]
                sibling_path.append(
                    {
                        "hash": sibling[0].hex(),
                        "sum": sibling[1],
                        "is_left": sibling_index < local_index,
                    }
                )
                local_index //= 2
            break

        peaks = [{"hash": node[0].hex(), "sum": node[1]} for node in self.peaks]
        return sibling_path, peaks


async def submit_to_ots(digest: bytes) -> bytes:
    """
    Submits a 32-byte digest to public OpenTimestamps calendar servers.
    Returns the binary content of the pending .ots file, or raises on failure.
    """
    calendars = [
        "https://alice.btc.calendar.opentimestamps.org/digest",
        "https://bob.btc.calendar.opentimestamps.org/digest",
    ]
    for url in calendars:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    content=digest,
                    headers={"Content-Type": "application/octet-stream"},
                )
                if response.status_code == 200 and len(response.content) > 0:
                    logger.info(f"Successfully obtained OTS timestamp from {url}")
                    return response.content
        except Exception as e:
            logger.warning(f"Failed to submit to OTS calendar {url}: {e}")
            continue

    raise ConnectionError(
        "All OTS calendar servers failed. Unable to obtain on-chain proof of existence."
    )


async def upgrade_ots_receipt(receipt: bytes) -> bytes:
    """Ask public calendars to upgrade a pending OTS receipt."""
    calendars = [
        "https://alice.btc.calendar.opentimestamps.org/upgrade",
        "https://bob.btc.calendar.opentimestamps.org/upgrade",
    ]
    for url in calendars:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    url,
                    content=receipt,
                    headers={"Content-Type": "application/octet-stream"},
                )
            if response.status_code == 200 and len(response.content) > len(receipt):
                return response.content
        except Exception as exc:
            logger.warning(f"Failed to upgrade OTS receipt at {url}: {exc}")
    return receipt


async def upgrade_pending_ots_receipts(ledger: Ledger) -> None:
    """Upgrade and republish pending receipts shared by synchronized epochs."""
    try:
        rows = await ledger.db.fetchall(
            f"SELECT DISTINCT epoch_index, ots_receipt FROM {ledger.db.table_with_schema('pol_epochs')}"
        )
        for row in rows:
            receipt = bytes.fromhex(row["ots_receipt"])
            if b"\x00\x06" not in receipt:
                continue
            upgraded = await upgrade_ots_receipt(receipt)
            if upgraded == receipt:
                continue
            await ledger.db.execute(
                f"UPDATE {ledger.db.table_with_schema('pol_epochs')} "
                "SET ots_receipt = :ots_receipt WHERE epoch_index = :epoch_index",
                {
                    "ots_receipt": upgraded.hex(),
                    "epoch_index": row["epoch_index"],
                },
            )
    except Exception as exc:
        logger.warning(f"Unable to upgrade pending PoL OTS receipts: {exc}")


def get_mint_signing_key(ledger: Ledger) -> Tuple[PrivateKey, str]:
    signing_key = PrivateKey(hashlib.sha256(ledger.seed.encode("utf-8")).digest())
    pub_key_hex = ledger.pubkey.format()[1:].hex()
    return signing_key, pub_key_hex


async def get_target_epoch(ledger: Ledger) -> int:
    latest = await get_latest_global_pol_epoch(ledger)
    if latest is None:
        return 1
    return latest["epoch_index"] + 1


async def generate_output_receipt(
    ledger: Ledger, keyset_id: str, amount: int, b_hex: str
) -> PolReceipt:
    target_epoch = await get_target_epoch(ledger)
    msg = f"Cashu_PoL_Receipt_Issued:{b_hex.lower()}:{target_epoch}"

    keyset = ledger.keysets[keyset_id]
    private_key = keyset.private_keys[amount]

    sig = private_key.sign_schnorr(hashlib.sha256(msg.encode("utf-8")).digest()).hex()
    return PolReceipt(target_epoch=target_epoch, signature=sig)


async def generate_spent_receipt(
    ledger: Ledger, keyset_id: str, amount: int, y_hex: str
) -> PolReceipt:
    target_epoch = await get_target_epoch(ledger)
    msg = f"Cashu_PoL_Receipt_Spent:{y_hex.lower()}:{target_epoch}"

    keyset = ledger.keysets[keyset_id]
    private_key = keyset.private_keys[amount]

    sig = private_key.sign_schnorr(hashlib.sha256(msg.encode("utf-8")).digest()).hex()
    return PolReceipt(target_epoch=target_epoch, signature=sig)


def parse_db_timestamp(val) -> datetime.datetime:
    if isinstance(val, datetime.datetime):
        return val
    if isinstance(val, (int, float)):
        return datetime.datetime.fromtimestamp(val, datetime.timezone.utc)
    if isinstance(val, str):
        try:
            return datetime.datetime.fromisoformat(val)
        except Exception:
            try:
                return datetime.datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
            except Exception:
                pass
    return datetime.datetime.now(datetime.timezone.utc)


async def get_latest_pol_epoch(ledger: Ledger, keyset_id: str) -> Optional[Dict]:
    if ledger.db is None:
        return None
    row = await ledger.db.fetchone(
        f"SELECT * FROM {ledger.db.table_with_schema('pol_epochs')} WHERE keyset_id = :keyset_id ORDER BY epoch_index DESC LIMIT 1",
        {"keyset_id": keyset_id},
    )
    return dict(row) if row else None


async def get_latest_global_pol_epoch(ledger: Ledger) -> Optional[Dict]:
    if ledger.db is None:
        return None
    row = await ledger.db.fetchone(
        f"SELECT * FROM {ledger.db.table_with_schema('pol_epochs')} ORDER BY timestamp DESC LIMIT 1"
    )
    return dict(row) if row else None


async def get_pol_epoch_by_index(
    ledger: Ledger, keyset_id: str, epoch_index: int
) -> Optional[Dict]:
    if ledger.db is None:
        return None
    row = await ledger.db.fetchone(
        f"SELECT * FROM {ledger.db.table_with_schema('pol_epochs')} WHERE keyset_id = :keyset_id AND epoch_index = :epoch_index",
        {"keyset_id": keyset_id, "epoch_index": epoch_index},
    )
    return dict(row) if row else None


async def build_trees_for_keyset_at_timestamp(
    ledger: Ledger,
    keyset_id: str,
    timestamp_limit: Optional[datetime.datetime] = None,
    epoch_index: Optional[int] = None,
) -> Tuple[MerkleMountainRangeSum, MerkleMountainRangeSum]:
    """
    Builds the Issued (promises) and Spent (proofs_used) sum-MMRs for a given keyset,
    optionally limiting to items created up to a specific timestamp (at the end of an epoch).
    """
    cache_key = f"{keyset_id}:{epoch_index}" if epoch_index is not None else None

    # 1. ATTEMPT PRIMARY REDIS CACHE (If enabled and initialized)
    if cache_key and settings.mint_redis_cache_enabled:
        if redis.initialized:
            try:
                issued_redis_key = f"pol:tree:issued:{cache_key}"
                spent_redis_key = f"pol:tree:spent:{cache_key}"

                issued_data = await redis.redis.get(issued_redis_key)
                spent_data = await redis.redis.get(spent_redis_key)

                if issued_data and spent_data:
                    logger.debug(
                        f"PoL cache hit in Redis for keyset {keyset_id} epoch {epoch_index}"
                    )
                    issued_tree = pickle.loads(issued_data)
                    spent_tree = pickle.loads(spent_data)
                    return issued_tree, spent_tree
            except Exception as e:
                logger.warning(f"Error accessing Redis cache for PoL trees: {e}")

    # 2. ATTEMPT FALLBACK IN-MEMORY CACHE (If Redis is NOT enabled/initialized)
    elif cache_key:
        if cache_key in _FALLBACK_MEM_CACHE:
            logger.debug(
                f"PoL cache hit in-memory fallback for keyset {keyset_id} epoch {epoch_index}"
            )
            return _FALLBACK_MEM_CACHE[cache_key]

    logger.debug(
        f"Building sum-MMRs for keyset {keyset_id} (timestamp limit: {timestamp_limit})"
    )
    if ledger.db is None:
        return MerkleMountainRangeSum([]), MerkleMountainRangeSum([])

    promises_rows = await ledger.db.fetchall(
        f"SELECT amount, b_, created FROM {ledger.db.table_with_schema('promises')} WHERE id = :keyset_id ORDER BY CASE WHEN pol_sequence IS NULL THEN 0 ELSE 1 END ASC, pol_sequence ASC, created ASC, order_index ASC, b_ ASC",
        {"keyset_id": keyset_id},
    )
    proofs_rows = await ledger.db.fetchall(
        f"SELECT amount, secret, y, created FROM {ledger.db.table_with_schema('proofs_used')} WHERE id = :keyset_id ORDER BY CASE WHEN pol_sequence IS NULL THEN 0 ELSE 1 END ASC, pol_sequence ASC, created ASC, y ASC",
        {"keyset_id": keyset_id},
    )
    logger.debug(
        f"Loaded {len(promises_rows)} promises and {len(proofs_rows)} spent proofs from the database."
    )
    issued_leaves: List[Node] = []
    for row in promises_rows:
        created_val = row.get("created")
        if timestamp_limit and created_val:
            created_dt = parse_db_timestamp(created_val)
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=datetime.timezone.utc)
            if timestamp_limit.tzinfo is None:
                timestamp_limit = timestamp_limit.replace(tzinfo=datetime.timezone.utc)
            if created_dt > timestamp_limit:
                continue

        amount = int(row["amount"])
        b_hex = row["b_"]

        # PoL Debug: Randomly forget to include with certain probability
        forget_prob = settings.mint_pol_forget_probability
        if forget_prob > 0.0 and random.random() < forget_prob:
            logger.warning(
                f"PoL DEBUG: Randomly forgetting to include promise with b_hex={b_hex} in Issued Tree."
            )
            continue

        # PoL Debug: Randomly cheat/alter the value of the promise
        cheat_prob = settings.mint_pol_cheat_value_probability
        if cheat_prob > 0.0 and random.random() < cheat_prob:
            original_amount = amount
            diff = random.choice([-1, 1])
            amount = max(0, amount + diff)
            if amount == original_amount:
                amount += 1
            logger.warning(
                f"PoL DEBUG: Cheating by changing promise value from {original_amount} to {amount} for b_hex={b_hex} in Issued Tree."
            )

        h_b = hashlib.sha256(bytes.fromhex(b_hex)).digest()
        issued_leaves.append((h_b, amount))

    spent_leaves: List[Node] = []
    for row in proofs_rows:
        created_val = row.get("created")
        if timestamp_limit and created_val:
            created_dt = parse_db_timestamp(created_val)
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=datetime.timezone.utc)
            if timestamp_limit.tzinfo is None:
                timestamp_limit = timestamp_limit.replace(tzinfo=datetime.timezone.utc)
            if created_dt > timestamp_limit:
                continue

        amount = int(row["amount"])
        secret = row["secret"]
        y_hex = row.get("y")
        if not y_hex:
            y_hex = hash_to_curve(secret.encode("utf-8")).format().hex()

        # PoL Debug: Randomly forget to include with certain probability
        forget_prob = settings.mint_pol_forget_probability
        if forget_prob > 0.0 and random.random() < forget_prob:
            logger.warning(
                f"PoL DEBUG: Randomly forgetting to include spent proof with secret={secret} / y_hex={y_hex} in Spent Tree."
            )
            continue

        # PoL Debug: Randomly cheat/alter the value of the spent proof
        cheat_prob = settings.mint_pol_cheat_value_probability
        if cheat_prob > 0.0 and random.random() < cheat_prob:
            original_amount = amount
            diff = random.choice([-1, 1])
            amount = max(0, amount + diff)
            if amount == original_amount:
                amount += 1
            logger.warning(
                f"PoL DEBUG: Cheating by changing spent proof value from {original_amount} to {amount} for secret={secret} / y_hex={y_hex} in Spent Tree."
            )

        h_y = hashlib.sha256(bytes.fromhex(y_hex)).digest()
        spent_leaves.append((h_y, amount))

    issued_tree = MerkleMountainRangeSum(issued_leaves)
    spent_tree = MerkleMountainRangeSum(spent_leaves)
    logger.debug(
        f"Constructed Issued MMR with {len(issued_leaves)} leaves and Spent MMR with {len(spent_leaves)} leaves."
    )

    # 3. POPULATE THE APPROPRIATE CACHE
    if cache_key:
        if settings.mint_redis_cache_enabled:
            if redis.initialized:
                try:
                    issued_redis_key = f"pol:tree:issued:{cache_key}"
                    spent_redis_key = f"pol:tree:spent:{cache_key}"

                    await redis.redis.set(
                        issued_redis_key,
                        pickle.dumps(issued_tree),
                        ex=settings.mint_redis_cache_ttl,
                    )
                    await redis.redis.set(
                        spent_redis_key,
                        pickle.dumps(spent_tree),
                        ex=settings.mint_redis_cache_ttl,
                    )
                    logger.debug(
                        f"PoL trees successfully cached in Redis for keyset {keyset_id} epoch {epoch_index}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to write PoL trees to Redis: {e}")
        else:
            _FALLBACK_MEM_CACHE[cache_key] = (issued_tree, spent_tree)
            # Prevent unbounded growth of the local fallback cache
            if len(_FALLBACK_MEM_CACHE) > 20:
                _FALLBACK_MEM_CACHE.pop(next(iter(_FALLBACK_MEM_CACHE)))
            logger.debug(
                f"PoL trees successfully cached in-memory for keyset {keyset_id} epoch {epoch_index}"
            )

    return issued_tree, spent_tree


async def get_global_digest_for_epoch(ledger: Ledger, epoch_index: int) -> bytes:
    if epoch_index <= 0:
        return b"\x00" * 32

    # Fetch all entries for this epoch index
    rows = await ledger.db.fetchall(
        f"SELECT keyset_id, issued_mmr_size, root_issued_hash, spent_mmr_size, root_spent_hash, previous_global_digest FROM {ledger.db.table_with_schema('pol_epochs')} WHERE epoch_index = :epoch_index",
        {"epoch_index": epoch_index},
    )
    if not rows:
        return b"\x00" * 32

    # Reconstruct the commitment
    # Sort them by keyset_id
    sorted_rows = sorted(rows, key=lambda r: r["keyset_id"].lower())

    # Since all rows in the same epoch share the same previous_global_digest, we take it from the first one
    prev_digest_hex = sorted_rows[0]["previous_global_digest"]
    prev_digest_bytes = bytes.fromhex(prev_digest_hex)

    global_commitment_data = prev_digest_bytes
    for row in sorted_rows:
        kid = row["keyset_id"].lower()
        ri_hash = bytes.fromhex(row["root_issued_hash"])
        rs_hash = bytes.fromhex(row["root_spent_hash"])
        global_commitment_data += (
            kid.encode("utf-8")
            + int(row["issued_mmr_size"]).to_bytes(8, "big")
            + ri_hash
            + int(row["spent_mmr_size"]).to_bytes(8, "big")
            + rs_hash
        )

    return hashlib.sha256(global_commitment_data).digest()


async def update_pol_manifests(ledger: Ledger) -> None:
    """
    Periodically checks all active and inactive (but not yet expired) keysets.
    Aggregates their roots together into a single deterministic global digest.
    Submits ONE single aggregated OpenTimestamps request for all keysets,
    and publishes the synchronized epoch manifests.
    """
    await upgrade_pending_ots_receipts(ledger)
    pol_epoch_seconds = settings.mint_pol_epoch_seconds or 86400
    current_time = datetime.datetime.now(datetime.timezone.utc)
    current_timestamp = int(time.time())

    # 1. Determine if a new epoch is due globally
    latest_global_epoch = await get_latest_global_pol_epoch(ledger)
    should_publish = False
    next_epoch_index = 1

    if latest_global_epoch is None:
        should_publish = True
        next_epoch_index = 1
    else:
        last_epoch_time = parse_db_timestamp(latest_global_epoch["timestamp"])
        if last_epoch_time.tzinfo is None:
            last_epoch_time = last_epoch_time.replace(tzinfo=datetime.timezone.utc)

        elapsed = (current_time - last_epoch_time).total_seconds()
        if elapsed >= pol_epoch_seconds:
            should_publish = True
            next_epoch_index = latest_global_epoch["epoch_index"] + 1

    if not should_publish:
        return

    logger.info(
        f"Publishing synchronized PoL epoch {next_epoch_index} for all keysets..."
    )

    keyset_results = {}

    # 2. Build trees and retrieve roots for all non-expired keysets
    for keyset_id, keyset in ledger.keysets.items():
        if keyset.final_expiry and current_timestamp > keyset.final_expiry:
            logger.debug(f"Keyset {keyset_id} is fully expired. Skipping.")
            continue

        try:
            issued_tree, spent_tree = await build_trees_for_keyset_at_timestamp(
                ledger, keyset_id, current_time, epoch_index=next_epoch_index
            )
            root_issued_hash, root_issued_sum = issued_tree.root
            root_spent_hash, root_spent_sum = spent_tree.root
            keyset_results[keyset_id.lower()] = (
                issued_tree.size,
                root_issued_hash,
                root_issued_sum,
                spent_tree.size,
                root_spent_hash,
                root_spent_sum,
                keyset,
            )
        except Exception as e:
            logger.error(f"Failed to build trees for keyset {keyset_id}: {e}")

    if not keyset_results:
        logger.debug(
            "No active or unexpired keysets found to commit. Skipping epoch publication."
        )
        return

    # 3. Create a single aggregated global digest in deterministic order
    sorted_keyset_ids = sorted(keyset_results)
    previous_epoch_index = next_epoch_index - 1
    previous_global_digest = await get_global_digest_for_epoch(
        ledger, previous_epoch_index
    )
    previous_global_digest_hex = previous_global_digest.hex()

    global_commitment_data = previous_global_digest
    for kid in sorted_keyset_ids:
        issued_size, ri_hash, _, spent_size, rs_hash, _, _ = keyset_results[kid]
        global_commitment_data += (
            kid.encode("utf-8")
            + issued_size.to_bytes(8, "big")
            + ri_hash
            + spent_size.to_bytes(8, "big")
            + rs_hash
        )

    global_digest = hashlib.sha256(global_commitment_data).digest()

    # 4. Obtain the SINGLE OTS receipt for all keysets
    try:
        if settings.mint_pol_mock_ots:
            logger.info("Mock OTS is enabled. Generating fake OTS receipt.")
            ots_receipt = (
                b"\x00" * 8
                + b"MOCK_OTS_RECEIPT_FOR_HASH_"
                + global_digest.hex().encode("utf-8")
            )
        else:
            ots_receipt = await submit_to_ots(global_digest)
        ots_receipt_hex = ots_receipt.hex()
    except Exception as e:
        logger.error(f"Failed to obtain aggregated OTS attestation: {e}")
        return

    # 5. Sign and save synchronized manifests for each keyset to the database
    for kid in sorted_keyset_ids:
        issued_size, ri_hash, ri_sum, spent_size, rs_hash, rs_sum, keyset = (
            keyset_results[kid]
        )
        outstanding_balance = ri_sum - rs_sum

        signing_key, pub_key_hex = get_mint_signing_key(ledger)

        current_time_utc = current_time.astimezone(datetime.timezone.utc)
        timestamp_str = current_time_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Formatted details to sign (excludes ots_receipt)
        data_to_sign = f"{kid}:{next_epoch_index}:{timestamp_str}:{previous_global_digest_hex}:{issued_size}:{ri_hash.hex()}:{ri_sum}:{spent_size}:{rs_hash.hex()}:{rs_sum}:{outstanding_balance}"
        signature = signing_key.sign_schnorr(
            hashlib.sha256(data_to_sign.encode("utf-8")).digest()
        ).hex()

        # Save to SQLite table
        await ledger.db.execute(
            f"""
            INSERT INTO {ledger.db.table_with_schema("pol_epochs")} (
                keyset_id, epoch_index, timestamp, previous_global_digest,
                issued_mmr_size, root_issued_hash, root_issued_sum,
                spent_mmr_size, root_spent_hash, root_spent_sum,
                outstanding_balance, ots_receipt, signature
            ) VALUES (
                :keyset_id, :epoch_index, :timestamp, :previous_global_digest,
                :issued_mmr_size, :root_issued_hash, :root_issued_sum,
                :spent_mmr_size, :root_spent_hash, :root_spent_sum,
                :outstanding_balance, :ots_receipt, :signature
            )
            """,
            {
                "keyset_id": kid,
                "epoch_index": next_epoch_index,
                "timestamp": current_time,
                "previous_global_digest": previous_global_digest_hex,
                "issued_mmr_size": issued_size,
                "root_issued_hash": ri_hash.hex(),
                "root_issued_sum": ri_sum,
                "spent_mmr_size": spent_size,
                "root_spent_hash": rs_hash.hex(),
                "root_spent_sum": rs_sum,
                "outstanding_balance": outstanding_balance,
                "ots_receipt": ots_receipt_hex,
                "signature": signature,
            },
        )

        logger.info(
            f"PoL Keyset {kid} synchronized manifest successfully saved in database for Epoch {next_epoch_index}!"
        )
