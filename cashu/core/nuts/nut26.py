import struct
from typing import List, Optional, Tuple

from bech32 import (
    CHARSET,
    bech32_decode,
    bech32_encode as _bech32_encode,
    bech32_hrp_expand,
    bech32_polymod,
    convertbits,
)

from .nut18 import NUT10Option, PaymentRequest, Transport

BECH32M_CONST = 0x2BC830A3
HRP = "creqb"

TRANSPORT_KINDS = {"nostr": 0, "post": 1}
TRANSPORT_KINDS_REV = {0: "nostr", 1: "post"}

NUT10_KINDS = {"P2PK": 0, "HTLC": 1}
NUT10_KINDS_REV = {0: "P2PK", 1: "HTLC"}


# ─── Bech32m ────────────────────────────────────────────────────────

def _bech32m_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + list(data)
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _bech32m_verify_checksum(hrp: str, data: List[int]) -> bool:
    return bech32_polymod(bech32_hrp_expand(hrp) + list(data)) == BECH32M_CONST

def bech32m_encode(hrp: str, data: List[int]) -> str:
    combined = list(data) + _bech32m_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32m_decode(bech: str) -> Tuple[Optional[str], Optional[List[int]]]:
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return (None, None)
    if bech.lower() != bech and bech.upper() != bech:
        return (None, None)
    bech_lower = bech.lower()
    pos = bech_lower.rfind("1")
    if pos < 1 or pos + 7 > len(bech_lower):
        return (None, None)
    if not all(x in CHARSET for x in bech_lower[pos + 1 :]):
        return (None, None)
    hrp = bech_lower[:pos]
    data = [CHARSET.find(x) for x in bech_lower[pos + 1 :]]
    if not _bech32m_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])


# ─── TLV primitives ─────────────────────────────────────────────────

def _tlv_entry(tag: int, value: bytes) -> bytes:
    return struct.pack(">BH", tag, len(value)) + value

def _tlv_parse(data: bytes) -> List[Tuple[int, bytes]]:
    entries: List[Tuple[int, bytes]] = []
    pos = 0
    while pos < len(data):
        tag = data[pos]
        length = struct.unpack(">H", data[pos + 1 : pos + 3])[0]
        value = data[pos + 3 : pos + 3 + length]
        entries.append((tag, value))
        pos += 3 + length
    return entries

# ─── Tag tuple encoding ─────────────────────────────────────────────

def _encode_tag_tuple(tag: List[str]) -> bytes:
    key = tag[0].encode()
    out = bytes([len(key)]) + key
    for v in tag[1:]:
        vb = v.encode()
        out += bytes([len(vb)]) + vb
    return out

def _decode_tag_tuple(data: bytes) -> List[str]:
    pos = 0
    kl = data[pos]
    pos += 1
    key = data[pos : pos + kl].decode()
    pos += kl
    result = [key]
    while pos < len(data):
        vl = data[pos]
        pos += 1
        result.append(data[pos : pos + vl].decode())
        pos += vl
    return result

# ─── Nostr helpers ───────────────────────────────────────────────────

def _parse_nostr_target(target_str: str) -> Tuple[bytes, List[str]]:
    """Parse npub/nprofile -> (32-byte pubkey, relay_urls)."""
    hrp, data = bech32_decode(target_str)
    if hrp is None or data is None:
        raise ValueError(f"Invalid nostr target: {target_str}")
    raw = bytes(convertbits(data, 5, 8, False) or [])

    if hrp == "npub":
        return (raw, [])

    # nprofile: NIP-19 TLV (1-byte type, 1-byte length)
    pubkey = b""
    relays: List[str] = []
    pos = 0
    while pos < len(raw):
        t = raw[pos]
        pos += 1
        l = raw[pos]
        pos += 1
        v = raw[pos : pos + l]
        pos += l
        if t == 0:
            pubkey = v
        elif t == 1:
            relays.append(v.decode())
    return (pubkey, relays)

def _encode_nostr_target(pubkey: bytes, relays: List[str]) -> str:
    """Encode 32-byte pubkey + relays -> npub or nprofile."""
    if not relays:
        five = convertbits(pubkey, 8, 5)
        assert five is not None
        return _bech32_encode("npub", five)

    # NIP-19 TLV for nprofile
    tlv = bytes([0, len(pubkey)]) + pubkey
    for r in relays:
        rb = r.encode()
        tlv += bytes([1, len(rb)]) + rb
    five = convertbits(tlv, 8, 5)
    assert five is not None
    return _bech32_encode("nprofile", five)

# ─── Transport encode/decode ────────────────────────────────────────

def _encode_transport(tr: Transport) -> bytes:
    kind = TRANSPORT_KINDS.get(tr.t)
    if kind is None:
        raise ValueError(f"Unknown transport type: {tr.t}")

    inner = _tlv_entry(0x01, bytes([kind]))

    if kind == 0:  # nostr
        pubkey, relays = _parse_nostr_target(tr.a)
        inner += _tlv_entry(0x02, pubkey)
        for relay in relays:
            inner += _tlv_entry(0x03, _encode_tag_tuple(["r", relay]))
    else:  # http_post
        inner += _tlv_entry(0x02, tr.a.encode())

    if tr.g:
        for tag in tr.g:
            inner += _tlv_entry(0x03, _encode_tag_tuple(tag))

    return inner

def _decode_transport(data: bytes) -> Transport:
    entries = _tlv_parse(data)
    kind: Optional[int] = None
    target_raw = b""
    tag_tuples: List[List[str]] = []

    for tag, val in entries:
        if tag == 0x01:
            kind = val[0]
        elif tag == 0x02:
            target_raw = val
        elif tag == 0x03:
            tag_tuples.append(_decode_tag_tuple(val))

    type_str = TRANSPORT_KINDS_REV.get(kind, "unknown")  # type: ignore

    if kind == 0:  # nostr
        relays = [t[1] for t in tag_tuples if t[0] == "r"]
        other_tags = [t for t in tag_tuples if t[0] != "r"]
        target = _encode_nostr_target(target_raw, relays)
    else:
        target = target_raw.decode()
        other_tags = tag_tuples

    return Transport(
        t=type_str,
        a=target,
        g=other_tags if other_tags else None,
    )

# ─── NUT-10 encode/decode ───────────────────────────────────────────

def _encode_nut10(opt: NUT10Option) -> bytes:
    kind = NUT10_KINDS.get(opt.k)
    if kind is None:
        raise ValueError(f"Unknown NUT-10 kind: {opt.k}")

    inner = _tlv_entry(0x01, bytes([kind]))
    inner += _tlv_entry(0x02, opt.d.encode())

    if opt.t:
        for tag in opt.t:
            inner += _tlv_entry(0x03, _encode_tag_tuple(tag))

    return inner

def _decode_nut10(data: bytes) -> NUT10Option:
    entries = _tlv_parse(data)
    kind: Optional[int] = None
    d = ""
    tags: List[List[str]] = []

    for tag, val in entries:
        if tag == 0x01:
            kind = val[0]
        elif tag == 0x02:
            d = val.decode()
        elif tag == 0x03:
            tags.append(_decode_tag_tuple(val))

    return NUT10Option(
        k=NUT10_KINDS_REV.get(kind, str(kind)),  # type: ignore
        d=d,
        t=tags if tags else None,
    )

# ─── PaymentRequest <-> TLV bytes ───────────────────────────────────

def _pr_to_tlv(pr: PaymentRequest) -> bytes:
    out = b""
    if pr.i is not None:
        out += _tlv_entry(0x01, pr.i.encode())
    if pr.a is not None:
        out += _tlv_entry(0x02, struct.pack(">Q", pr.a))
    if pr.u is not None:
        if pr.u == "sat":
            out += _tlv_entry(0x03, bytes([0x00]))
        else:
            out += _tlv_entry(0x03, pr.u.encode())
    if pr.s is not None:
        out += _tlv_entry(0x04, bytes([1 if pr.s else 0]))
    if pr.m:
        for mint in pr.m:
            out += _tlv_entry(0x05, mint.encode())
    if pr.d is not None:
        out += _tlv_entry(0x06, pr.d.encode())
    if pr.t:
        for tr in pr.t:
            out += _tlv_entry(0x07, _encode_transport(tr))
    if pr.nut10 is not None:
        out += _tlv_entry(0x08, _encode_nut10(pr.nut10))
    return out

def _tlv_to_pr(data: bytes) -> PaymentRequest:
    entries = _tlv_parse(data)
    kwargs: dict = {}
    mints: List[str] = []
    transports: List[Transport] = []

    for tag, val in entries:
        if tag == 0x01:
            kwargs["i"] = val.decode()
        elif tag == 0x02:
            kwargs["a"] = struct.unpack(">Q", val)[0]
        elif tag == 0x03:
            if len(val) == 1 and val[0] == 0x00:
                kwargs["u"] = "sat"
            else:
                kwargs["u"] = val.decode()
        elif tag == 0x04:
            kwargs["s"] = val[0] == 1
        elif tag == 0x05:
            mints.append(val.decode())
        elif tag == 0x06:
            kwargs["d"] = val.decode()
        elif tag == 0x07:
            transports.append(_decode_transport(val))
        elif tag == 0x08:
            kwargs["nut10"] = _decode_nut10(val)

    if mints:
        kwargs["m"] = mints
    if transports:
        kwargs["t"] = transports

    return PaymentRequest(**kwargs)

# ─── Public API ──────────────────────────────────────────────────────

def serialize(pr: PaymentRequest) -> str:
    """Serialize a PaymentRequest to NUT-26 Bech32m format (uppercase)."""
    raw = _pr_to_tlv(pr)
    five_bit = convertbits(raw, 8, 5)
    assert five_bit is not None
    return bech32m_encode(HRP, five_bit).upper()

def deserialize(token: str) -> PaymentRequest:
    """Deserialize a NUT-26 Bech32m payment request."""
    hrp, data = bech32m_decode(token)
    if hrp.lower() != HRP or data is None:
        raise ValueError("Invalid Bech32m payment request")
    raw = convertbits(data, 5, 8, False)
    if raw is None:
        raise ValueError("Invalid Bech32m data")
    return _tlv_to_pr(bytes(raw))
