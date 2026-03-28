import pytest

from cashu.core.nuts.nut18 import deserialize, serialize
from cashu.core.nuts.nut26 import bech32m_decode
from cashu.core.nuts.nut26 import serialize as serialize_bech32m
from cashu.core.nuts.payment_request import NUT10Option, PaymentRequest, Transport


def test_nut18_serialization_example():
    # Example from NUT-18 spec
    req = PaymentRequest(
        i="b7a90176",
        a=10,
        u="sat",
        m=["https://nofees.testnut.cashu.space"],
        t=[
            Transport(
                t="nostr",
                a="nprofile1qy28wumn8ghj7un9d3shjtnyv9kh2uewd9hsz9mhwden5te0wfjkccte9curxven9eehqctrv5hszrthwden5te0dehhxtnvdakqqgydaqy7curk439ykptkysv7udhdhu68sucm295akqefdehkf0d495cwunl5",
                g=[["n", "17"]]
            )
        ]
    )
    
    encoded = serialize(req)
    # expected_encoded = "creqApWF0gaNhdGVub3N0cmFheKlucHJvZmlsZTFxeTI4d3VtbjhnaGo3dW45ZDNzaGp0bnl2OWtoMnVld2Q5aHN6OW1od2RlbjV0ZTB3ZmprY2N0ZTljdXJ4dmVuOWVlaHFjdHJ2NWhzenJ0aHdkZW41dGUwZGVoaHh0bnZkYWtxcWd5ZGFxeTdjdXJrNDM5eWtwdGt5c3Y3dWRoZGh1NjhzdWNtMjk1YWtxZWZkZWhrZjBkNDk1Y3d1bmw1YWeBgmFuYjE3YWloYjdhOTAxNzZhYQphdWNzYXRhbYF4Imh0dHBzOi8vbm9mZWVzLnRlc3RudXQuY2FzaHUuc3BhY2U"
    
    # NOTE: CBOR dict key order is generally undetermined unless canonical, 
    # but let's check if the fields match when deserialized
    
    decoded = deserialize(encoded)
    assert decoded.i == req.i
    assert decoded.a == req.a
    assert decoded.u == req.u
    assert decoded.m == req.m
    assert decoded.t[0].t == req.t[0].t
    assert decoded.t[0].a == req.t[0].a
    assert decoded.t[0].g == req.t[0].g

    # Test exact string match if deterministic
    # assert encoded == expected_encoded

def test_nut18_round_trip():
    req = PaymentRequest(
        a=100,
        u="usd",
        m=["https://mint.example.com"],
        d="Coffee"
    )
    serialized = serialize(req)
    assert serialized.startswith("creqA")
    
    decoded = deserialize(serialized)
    assert decoded.a == 100
    assert decoded.u == "usd"
    assert decoded.m == ["https://mint.example.com"]
    assert decoded.d == "Coffee"
    assert decoded.i is None


# ─── NUT-26 Tests ────────────────────────────────────────────────────
def test_nut26_spec_example():
    """Test the example from the NUT-26 spec."""
    expected = (
        "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQ"
        "VXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YP"
        "CXZ7TDV4H8GXHR3TQ"
    )
    req = PaymentRequest(
        i="demo123",
        a=1000,
        u="sat",
        s=True,
        m=["https://mint.example.com"],
        d="Coffee payment",
    )
    encoded = serialize_bech32m(req)
    assert encoded == expected


def test_nut26_spec_example_deserialize():
    """Deserialize the NUT-26 spec example."""
    token = (
        "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQ"
        "VXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YP"
        "CXZ7TDV4H8GXHR3TQ"
    )
    pr = deserialize(token)
    assert pr.i == "demo123"
    assert pr.a == 1000
    assert pr.u == "sat"
    assert pr.s is True
    assert pr.m == ["https://mint.example.com"]
    assert pr.d == "Coffee payment"


def test_nut26_round_trip_simple():
    req = PaymentRequest(
        a=100,
        u="usd",
        m=["https://mint.example.com"],
        d="Coffee",
    )
    serialized = serialize_bech32m(req)
    assert serialized.startswith("CREQB1")

    decoded = deserialize(serialized)
    assert decoded.a == 100
    assert decoded.u == "usd"
    assert decoded.m == ["https://mint.example.com"]
    assert decoded.d == "Coffee"
    assert decoded.i is None


def test_nut26_round_trip_sat_unit():
    """'sat' should encode compactly as 0x00."""
    req = PaymentRequest(a=21000, u="sat")
    serialized = serialize_bech32m(req)
    decoded = deserialize(serialized)
    assert decoded.a == 21000
    assert decoded.u == "sat"


def test_nut26_round_trip_multiple_mints():
    req = PaymentRequest(
        a=500,
        u="sat",
        m=["https://mint1.example.com", "https://mint2.example.com"],
    )
    decoded = deserialize(serialize_bech32m(req))
    assert decoded.m == ["https://mint1.example.com", "https://mint2.example.com"]


def test_nut26_round_trip_nut10():
    req = PaymentRequest(
        a=100,
        u="sat",
        nut10=NUT10Option(k="P2PK", d="abcdef1234567890" * 4),
    )
    decoded = deserialize(serialize_bech32m(req))
    assert decoded.nut10 is not None
    assert decoded.nut10.k == "P2PK"
    assert decoded.nut10.d == "abcdef1234567890" * 4


def test_nut26_case_insensitive_decode():
    """Bech32m decoding must accept both upper and lower case."""
    req = PaymentRequest(a=1, u="sat")
    upper = serialize_bech32m(req)  # uppercase by default
    lower = upper.lower()
    pr_upper = deserialize(upper)
    pr_lower = deserialize(lower)
    assert pr_upper.a == pr_lower.a == 1
    assert pr_upper.u == pr_lower.u == "sat"


def test_nut26_minimal_empty_request():
    """A payment request with no fields should round-trip."""
    req = PaymentRequest()
    decoded = deserialize(serialize_bech32m(req))
    assert decoded.a is None
    assert decoded.u is None
    assert decoded.m is None


# ─── NUT-26 Validation Tests ────────────────────────────────────────
def test_nut26_bech32m_rejects_invalid_checksum():
    """bech32m_decode must reject strings with an invalid checksum."""
    valid = serialize_bech32m(PaymentRequest(a=1, u="sat"))
    # Flip the last data character to corrupt the checksum
    corrupted = valid[:-1] + ("Q" if valid[-1] != "Q" else "P")
    hrp, data = bech32m_decode(corrupted)
    assert hrp is None and data is None


def test_nut26_bech32m_rejects_mixed_case():
    """bech32m_decode must reject mixed-case input."""
    # "Creqb1..." is mixed case — must be rejected
    valid_upper = serialize_bech32m(PaymentRequest(a=1, u="sat"))
    mixed = "c" + valid_upper[1:]  # lowercase first char, rest uppercase
    hrp, data = bech32m_decode(mixed)
    assert hrp is None and data is None


def test_nut26_deserialize_rejects_wrong_hrp():
    """deserialize must raise ValueError for non-creqb HRP."""
    with pytest.raises(ValueError):
        deserialize("creqx1qqqqqqqq")


def test_nut26_round_trip_id_only():
    """Minimal request with only an id field."""
    pr = PaymentRequest(i="demo123")
    decoded = deserialize(serialize_bech32m(pr))
    assert decoded.i == "demo123"
    assert decoded.a is None


def test_nut26_spec_example_full_round_trip():
    """Full spec example: encode, verify exact string, decode lowercase."""
    expected = (
        "CREQB1QYQQWER9D4HNZV3NQGQQSQQQQQQQQQQRAQPSQQGQQSQQZQG9QQ"
        "VXSAR5WPEN5TE0D45KUAPWV4UXZMTSD3JJUCM0D5RQQRJRDANXVET9YP"
        "CXZ7TDV4H8GXHR3TQ"
    )
    pr = PaymentRequest(
        i="demo123", a=1000, u="sat", s=True,
        m=["https://mint.example.com"], d="Coffee payment",
    )
    encoded = serialize_bech32m(pr)
    assert encoded.startswith("CREQB1")
    assert encoded == expected
    # lowercase must also decode identically
    decoded = deserialize(encoded.lower())
    assert decoded.i == pr.i
    assert decoded.a == pr.a
    assert decoded.u == pr.u
    assert decoded.s == pr.s
    assert decoded.m == pr.m
    assert decoded.d == pr.d