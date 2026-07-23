import json
import re
from typing import Any, List, Optional, Union

from ..crypto.secp import PublicKey
from ..errors import TransactionError
from ..htlc import HTLCSecret
from ..p2pk import P2PKSecret
from ..secret import Secret, SecretKind, parse_int_tag

SpendingCondition = Union[P2PKSecret, HTLCSecret]

_KNOWN_KIND_PREFIX = re.compile(r"^\s*\[\s*[\"']?(?:P2PK|HTLC)[\"']?\s*(?:,|\])")
_SINGLE_VALUE_TAGS = {"sigflag", "n_sigs", "locktime", "n_sigs_refund"}
_MULTI_VALUE_TAGS = {"pubkeys", "refund"}
_SUPPORTED_TAGS = _SINGLE_VALUE_TAGS | _MULTI_VALUE_TAGS


def parse_spending_condition(raw_secret: str) -> Optional[SpendingCondition]:
    """Parse and validate a NUT-10 spending condition.

    Returns ``None`` only when ``raw_secret`` is not a NUT-10 candidate. Once a
    secret declares a NUT-10 shape or a supported kind, malformed and unsupported
    conditions raise ``TransactionError`` instead of becoming ordinary secrets.
    """

    decoded = _decode_candidate(raw_secret)
    if decoded is None:
        return None

    try:
        kind, payload = _validate_envelope(decoded)
        _validate_tags(payload.get("tags", []))
        secret = Secret.deserialize(raw_secret)

        if kind == SecretKind.P2PK.value:
            condition: SpendingCondition = P2PKSecret.from_secret(secret)
        elif kind == SecretKind.HTLC.value:
            condition = HTLCSecret.from_secret(secret)
        else:
            raise TransactionError(f"unsupported NUT-10 secret kind: {kind}")

        _validate_condition(condition)
        return condition
    except TransactionError:
        raise
    except Exception as exc:
        raise TransactionError("malformed NUT-10 secret.") from exc


def _decode_candidate(raw_secret: str) -> Optional[List[Any]]:
    try:
        decoded = json.loads(raw_secret)
    except (json.JSONDecodeError, TypeError) as exc:
        if isinstance(raw_secret, str) and _KNOWN_KIND_PREFIX.match(raw_secret):
            raise TransactionError("malformed NUT-10 secret.") from exc
        return None

    if not isinstance(decoded, list):
        return None

    kind = decoded[0] if decoded and isinstance(decoded[0], str) else None
    has_supported_kind = kind in {kind.value for kind in SecretKind}
    has_nut10_shape = (
        len(decoded) == 2 and isinstance(kind, str) and isinstance(decoded[1], dict)
    )
    if not has_supported_kind and not has_nut10_shape:
        return None

    return json.loads(raw_secret, object_pairs_hook=_reject_duplicate_keys)


def _reject_duplicate_keys(pairs: List[tuple[str, Any]]) -> dict[str, Any]:
    decoded = {}
    for key, value in pairs:
        if key in decoded:
            raise TransactionError(f"malformed NUT-10 secret: duplicate {key} field.")
        decoded[key] = value
    return decoded


def _validate_envelope(decoded: List[Any]) -> tuple[str, dict]:
    if len(decoded) != 2:
        raise TransactionError("malformed NUT-10 secret: expected two elements.")

    kind, payload = decoded
    if not isinstance(kind, str) or not kind:
        raise TransactionError("malformed NUT-10 secret: invalid kind.")
    if not isinstance(payload, dict):
        raise TransactionError("malformed NUT-10 secret: invalid payload.")
    if set(payload) - {"nonce", "data", "tags"}:
        raise TransactionError("malformed NUT-10 secret: unexpected payload field.")

    for field in ("nonce", "data"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise TransactionError(f"malformed NUT-10 secret: invalid {field} field.")

    tags = payload.get("tags", [])
    if not isinstance(tags, list):
        raise TransactionError("malformed NUT-10 secret: invalid tags field.")

    return kind, payload


def _validate_tags(tags: List[Any]) -> None:
    seen_supported_tags = set()
    for tag in tags:
        if (
            not isinstance(tag, list)
            or not tag
            or not all(isinstance(value, str) and value for value in tag)
        ):
            raise TransactionError("malformed NUT-10 secret: invalid tag.")

        tag_name = tag[0]
        if tag_name not in _SUPPORTED_TAGS:
            continue
        if tag_name in seen_supported_tags:
            raise TransactionError(
                f"malformed NUT-10 secret: duplicate {tag_name} tag."
            )
        seen_supported_tags.add(tag_name)

        if tag_name in _SINGLE_VALUE_TAGS and len(tag) != 2:
            raise TransactionError(f"malformed NUT-10 secret: invalid {tag_name} tag.")
        if tag_name in _MULTI_VALUE_TAGS and len(tag) < 2:
            raise TransactionError(f"malformed NUT-10 secret: invalid {tag_name} tag.")


def _validate_condition(condition: SpendingCondition) -> None:
    pubkeys = condition.tags.get_tag_all("pubkeys")
    refund_pubkeys = condition.tags.get_tag_all("refund")

    if isinstance(condition, HTLCSecret):
        _validate_htlc_hash(condition.data)
        primary_pubkeys = pubkeys
    else:
        primary_pubkeys = [condition.data, *pubkeys]

    _validate_pubkey_path(primary_pubkeys)
    _validate_pubkey_path(refund_pubkeys)

    locktime = condition.tags.get_tag("locktime")
    if locktime is not None and parse_int_tag(locktime) is None:
        raise TransactionError("malformed NUT-10 secret: locktime must be an integer.")

    n_sigs = _positive_integer_tag(condition, "n_sigs")
    if n_sigs is not None and n_sigs > len(primary_pubkeys):
        raise TransactionError(
            "malformed NUT-10 secret: n_sigs exceeds available pubkeys."
        )

    n_sigs_refund = _positive_integer_tag(condition, "n_sigs_refund")
    if n_sigs_refund is not None and n_sigs_refund > len(refund_pubkeys):
        raise TransactionError(
            "malformed NUT-10 secret: n_sigs_refund exceeds available pubkeys."
        )


def _positive_integer_tag(condition: SpendingCondition, tag_name: str) -> Optional[int]:
    value = condition.tags.get_tag(tag_name)
    if value is None:
        return None
    parsed = parse_int_tag(value)
    if parsed is None or parsed <= 0:
        raise TransactionError(
            f"malformed NUT-10 secret: {tag_name} must be a positive integer."
        )
    return parsed


def _validate_pubkey_path(pubkeys: List[str]) -> None:
    normalized = [pubkey.lower() for pubkey in pubkeys]
    for pubkey in normalized:
        if len(pubkey) != 66 or pubkey[:2] not in {"02", "03"}:
            raise TransactionError(
                "malformed NUT-10 secret: invalid compressed public key."
            )
        try:
            PublicKey(bytes.fromhex(pubkey))
        except (TypeError, ValueError) as exc:
            raise TransactionError(
                "malformed NUT-10 secret: invalid compressed public key."
            ) from exc

    if len(set(normalized)) != len(normalized):
        raise TransactionError("pubkeys must be unique.")

    x_coordinates = [pubkey[2:] for pubkey in normalized]
    if len(set(x_coordinates)) != len(x_coordinates):
        raise TransactionError("pubkeys must have unique x-coordinates.")


def _validate_htlc_hash(data: str) -> None:
    if len(data) != 64 or data != data.lower():
        raise TransactionError("malformed NUT-10 secret: invalid HTLC hash.")
    try:
        bytes.fromhex(data)
    except ValueError as exc:
        raise TransactionError("malformed NUT-10 secret: invalid HTLC hash.") from exc
