"""NUT-22 version 02 blind authentication: request transcripts and witnesses.

Pins the nuts tests/22-tests.md vector byte for byte.
"""

import json

from cashu.core.base import AuthProof
from cashu.core.crypto.secp import PrivateKey
from cashu.core.crypto.transcript import build_request_transcript, request_digest
from cashu.core.nuts import nut22

# The shared vectors' v3 keyset id (a BLS keyset, version byte 02).
V3_KEYSET_ID = "02b7e077d020fabed456a6be138a8e20e9ef40b44d873fa12c005b656eb0cf99f6"

# nuts tests/22-tests.md: a BAT (secret key 3) authorizing POST /v1/swap.
VECTOR = {
    "secret": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "method": "POST",
    "target": "/v1/swap",
    "body": b"illustrative request body",
    "transcript": "050035010004504f53540200082f76312f73776170030020bc14236ec9e2bf6d961268b7463d7be83e01554adfd063361e9e3ae985edce19",
    "digest": "ed581b087f06e474da2417eaf96d358244cb1b1b14464b2e3d8706f9a67bc10c",
    "signature": "6a120a859e0cb85f9cb3d7a69c756d4f4f8ac0954785d7c9a9262ed937ddb3123d10a296a5ded693974f2b4722f89f9d00498d50f0706eb94bd967e5f3c7b85c",
}


# nuts tests/22-tests.md: the target is the origin-form request-target as sent,
# query string unsorted and percent-encoded as transmitted; no body.
QUERY_VECTOR = {
    "secret": "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
    "method": "GET",
    "target": "/v1/mint/quote/bolt11/quote123?b=2&a=1&q=a%20b",
    "body": b"",
    "transcript": "05005a01000347455402002e2f76312f6d696e742f71756f74652f626f6c7431312f71756f74653132333f623d3226613d3126713d6125323062030020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "digest": "6ed8e3a69429d4845ddcfa8728c7461c97b0c189592228c25266c630f62b1680",
    "signature": "9306bc19ad0e497185a34ec9a49de0bd8161bcdf1c58f0fd9f108a7603affb1d24b1a2fd6d513bf843ac92c29c95614beb535ace4e3a4a8677d688388209fb88",
}


def _vector_auth_proof(witness=None) -> AuthProof:
    return AuthProof(
        id=V3_KEYSET_ID, secret=VECTOR["secret"], C="00" * 48, witness=witness
    )


def _vector_witness() -> str:
    return json.dumps({"signatures": [VECTOR["signature"]]})


def test_request_transcript_pins_the_vector():
    transcript = build_request_transcript(
        VECTOR["method"], VECTOR["target"], VECTOR["body"]
    )
    assert transcript.hex() == VECTOR["transcript"]
    digest = request_digest(VECTOR["method"], VECTOR["target"], VECTOR["body"])
    assert digest.hex() == VECTOR["digest"]


def test_vector_witness_verifies():
    proof = _vector_auth_proof(witness=_vector_witness())
    assert nut22.verify_bat_request_witness(
        proof, VECTOR["method"], VECTOR["target"], VECTOR["body"]
    )


def test_witness_binds_the_request():
    proof = _vector_auth_proof(witness=_vector_witness())
    assert not nut22.verify_bat_request_witness(
        proof, "GET", VECTOR["target"], VECTOR["body"]
    )
    assert not nut22.verify_bat_request_witness(
        proof, VECTOR["method"], "/v1/melt/bolt11", VECTOR["body"]
    )
    assert not nut22.verify_bat_request_witness(
        proof, VECTOR["method"], VECTOR["target"], b"substituted body"
    )


def test_query_string_transcript_pins_the_vector():
    transcript = build_request_transcript(
        QUERY_VECTOR["method"], QUERY_VECTOR["target"], QUERY_VECTOR["body"]
    )
    assert transcript.hex() == QUERY_VECTOR["transcript"]
    digest = request_digest(
        QUERY_VECTOR["method"], QUERY_VECTOR["target"], QUERY_VECTOR["body"]
    )
    assert digest.hex() == QUERY_VECTOR["digest"]


def test_query_string_witness_verifies_as_sent_only():
    proof = AuthProof(
        id=V3_KEYSET_ID,
        secret=QUERY_VECTOR["secret"],
        C="00" * 48,
        witness=json.dumps({"signatures": [QUERY_VECTOR["signature"]]}),
    )
    assert nut22.verify_bat_request_witness(
        proof, QUERY_VECTOR["method"], QUERY_VECTOR["target"], QUERY_VECTOR["body"]
    )
    # A verifier rebuilding the target from parsed components must not re-sort
    # the parameters or re-encode the escapes.
    resorted = "/v1/mint/quote/bolt11/quote123?a=1&b=2&q=a%20b"
    assert not nut22.verify_bat_request_witness(
        proof, QUERY_VECTOR["method"], resorted, QUERY_VECTOR["body"]
    )
    reencoded = "/v1/mint/quote/bolt11/quote123?b=2&a=1&q=a+b"
    assert not nut22.verify_bat_request_witness(
        proof, QUERY_VECTOR["method"], reencoded, QUERY_VECTOR["body"]
    )


def test_witness_shape_is_enforced():
    # Missing witness, non-point secret, and more than one signature all reject.
    assert not nut22.verify_bat_request_witness(
        _vector_auth_proof(witness=None),
        VECTOR["method"],
        VECTOR["target"],
        VECTOR["body"],
    )
    string_secret = AuthProof(
        id=V3_KEYSET_ID, secret="ab" * 32, C="00" * 48, witness=_vector_witness()
    )
    assert not nut22.verify_bat_request_witness(
        string_secret, VECTOR["method"], VECTOR["target"], VECTOR["body"]
    )
    doubled = _vector_auth_proof(
        witness=json.dumps({"signatures": [VECTOR["signature"], "00" * 64]})
    )
    assert not nut22.verify_bat_request_witness(
        doubled, VECTOR["method"], VECTOR["target"], VECTOR["body"]
    )


def test_sign_request_roundtrip():
    key = PrivateKey()
    witness = nut22.sign_request(key, "POST", "/v1/melt/bolt11", b'{"quote":"x"}')
    proof = AuthProof(
        id=V3_KEYSET_ID,
        secret=key.public_key.format().hex(),
        C="00" * 48,
        witness=witness,
    )
    assert nut22.verify_bat_request_witness(
        proof, "POST", "/v1/melt/bolt11", b'{"quote":"x"}'
    )
    assert not nut22.verify_bat_request_witness(
        proof, "POST", "/v1/melt/bolt11", b'{"quote":"y"}'
    )


def test_auth_proof_serialization_carries_the_witness():
    proof = _vector_auth_proof(witness=_vector_witness())
    decoded = AuthProof.from_base64(proof.to_base64())
    assert decoded.witness == _vector_witness()
    # A pre-v3 BAT's encoding is unchanged: no witness key at all.
    legacy = AuthProof(id="009a1f29", secret="ab" * 32, C="02" + "cd" * 32)
    assert "witness" not in json.loads(
        __import__("base64").urlsafe_b64decode(
            legacy.to_base64()[len(AuthProof.prefix) :] + "=="
        )
    )


def test_batkey_derivation_record_roundtrip():
    key = PrivateKey()
    record = f"{nut22.BATKEY_PREFIX}{key.to_hex()}"
    recovered = nut22.bat_private_key(record)
    assert recovered is not None
    assert recovered.public_key.format().hex() == key.public_key.format().hex()
    assert nut22.bat_private_key("") is None
    assert nut22.bat_private_key("HMAC-SHA256:abc:1") is None
