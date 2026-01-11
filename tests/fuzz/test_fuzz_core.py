
from hypothesis import given
from hypothesis import strategies as st

from cashu.core.base import (
    DLEQ,
    BlindedMessage,
    BlindedSignature,
    DLEQWallet,
    MeltQuote,
    MeltQuoteState,
    MintKeyset,
    MintQuote,
    MintQuoteState,
    Proof,
    TokenV3,
    TokenV3Token,
    TokenV4,
    Unit,
    WalletKeyset,
)
from cashu.core.crypto.secp import PrivateKey
from cashu.core.secret import Secret, Tags


# Helpers
def hex_string(min_len=66, max_len=66):
    return st.text(alphabet="0123456789abcdef", min_size=min_len, max_size=max_len)

# --- Secret Strategies ---
@given(
    kind=st.text(min_size=1, max_size=20),
    data=st.text(min_size=1, max_size=100),
    tags_list=st.lists(st.lists(st.text(min_size=1, max_size=20), min_size=2, max_size=5), min_size=0, max_size=5),
    nonce=st.one_of(st.none(), hex_string(32, 32))
)
def test_fuzz_secret_serialization(kind, data, tags_list, nonce):
    tags = Tags(tags=tags_list)
    secret = Secret(kind=kind, data=data, tags=tags, nonce=nonce)
    
    # Serialize
    serialized = secret.serialize()
    
    # Deserialize
    deserialized = Secret.deserialize(serialized)
    
    # Check properties (ignoring nonce for equality if it was None originally and generated during serialization)
    assert deserialized.kind == kind
    assert deserialized.data == data
    assert deserialized.tags.root == tags_list
    
    # Verify equality method
    assert secret == deserialized
    assert hash(secret) == hash(deserialized)

# --- Base Model Strategies ---

@given(
    amount=st.integers(min_value=1),
    id=st.text(min_size=1, max_size=20),
    B_=hex_string(),
    C_=st.one_of(st.none(), hex_string())
)
def test_fuzz_blinded_message(amount, id, B_, C_):
    bm = BlindedMessage(amount=amount, id=id, B_=B_, C_=C_)
    assert bm.amount == amount
    assert bm.id == id
    assert bm.B_ == B_
    assert bm.C_ == C_
    
    # To dict and back (via Pydantic)
    d = bm.dict()
    bm2 = BlindedMessage.parse_obj(d)
    assert bm == bm2

@given(
    id=st.text(min_size=1, max_size=20),
    amount=st.integers(min_value=1),
    C_=hex_string(),
    dleq_e=hex_string(),
    dleq_s=hex_string()
)
def test_fuzz_blinded_signature(id, amount, C_, dleq_e, dleq_s):
    dleq = DLEQ(e=dleq_e, s=dleq_s)
    bs = BlindedSignature(id=id, amount=amount, C_=C_, dleq=dleq)
    
    assert bs.id == id
    assert bs.amount == amount
    assert bs.C_ == C_
    assert bs.dleq == dleq
    
    # Round trip
    bs2 = BlindedSignature.parse_obj(bs.dict())
    assert bs == bs2

@given(
    id=st.text(min_size=1, max_size=20),
    amount=st.integers(min_value=1),
    secret=st.text(min_size=1, max_size=64),
    C=hex_string(),
    dleq_e=hex_string(),
    dleq_s=hex_string(),
    dleq_r=hex_string()
)
def test_fuzz_proof(id, amount, secret, C, dleq_e, dleq_s, dleq_r):
    dleq = DLEQWallet(e=dleq_e, s=dleq_s, r=dleq_r)
    proof = Proof(id=id, amount=amount, secret=secret, C=C, dleq=dleq)
    
    assert proof.id == id
    assert proof.amount == amount
    assert proof.secret == secret
    assert proof.C == C
    assert proof.dleq == dleq
    
    # Test methods
    d_no_dleq = proof.to_dict(include_dleq=False)
    assert "dleq" not in d_no_dleq
    
    d_with_dleq = proof.to_dict(include_dleq=True)
    assert "dleq" in d_with_dleq
    
    # Serialization
    b64 = proof.to_base64()
    assert isinstance(b64, str)
    
    # Round trip via dict
    proof2 = Proof.from_dict(d_with_dleq)
    assert proof.id == proof2.id
    assert proof.amount == proof2.amount
    assert proof.secret == proof2.secret
    assert proof.C == proof2.C
    assert proof.dleq == proof2.dleq

@given(
    quote=st.text(min_size=1, max_size=50),
    method=st.text(min_size=1, max_size=10),
    request=st.text(min_size=10, max_size=100),
    checking_id=st.text(min_size=1, max_size=50),
    unit=st.sampled_from(["sat", "usd", "eur"]),
    amount=st.integers(min_value=1),
    fee_reserve=st.integers(min_value=0),
    state=st.sampled_from(list(MeltQuoteState))
)
def test_fuzz_melt_quote(quote, method, request, checking_id, unit, amount, fee_reserve, state):
    mq = MeltQuote(
        quote=quote,
        method=method,
        request=request,
        checking_id=checking_id,
        unit=unit,
        amount=amount,
        fee_reserve=fee_reserve,
        state=state
    )
    
    assert mq.quote == quote
    assert mq.state == state
    
    # Test property accessors
    if state == MeltQuoteState.paid:
        assert mq.paid
        assert not mq.unpaid
        assert not mq.pending
    elif state == MeltQuoteState.unpaid:
        assert not mq.paid
        assert mq.unpaid
        assert not mq.pending
    elif state == MeltQuoteState.pending:
        assert not mq.paid
        assert not mq.unpaid
        assert mq.pending

@given(
    quote=st.text(min_size=1, max_size=50),
    method=st.text(min_size=1, max_size=10),
    request=st.text(min_size=10, max_size=100),
    checking_id=st.text(min_size=1, max_size=50),
    unit=st.sampled_from(["sat", "usd", "eur"]),
    amount=st.integers(min_value=1),
    state=st.sampled_from(list(MintQuoteState))
)
def test_fuzz_mint_quote(quote, method, request, checking_id, unit, amount, state):
    mq = MintQuote(
        quote=quote,
        method=method,
        request=request,
        checking_id=checking_id,
        unit=unit,
        amount=amount,
        state=state
    )
    
    assert mq.quote == quote
    assert mq.state == state

    if state == MintQuoteState.paid:
        assert mq.paid
        assert not mq.unpaid
        assert not mq.pending
        assert not mq.issued
    elif state == MintQuoteState.unpaid:
        assert not mq.paid
        assert mq.unpaid
        assert not mq.pending
        assert not mq.issued
    elif state == MintQuoteState.pending:
        assert not mq.paid
        assert not mq.unpaid
        assert mq.pending
        assert not mq.issued
    elif state == MintQuoteState.issued:
        assert not mq.paid
        assert not mq.unpaid
        assert not mq.pending
        assert mq.issued

# --- Keyset & Token Strategies ---

# Strategy for PublicKey
@st.composite
def public_key_strategy(draw):
    priv = PrivateKey()
    return priv.public_key

@given(
    seed=st.text(min_size=5, max_size=32),
    derivation_path=st.just("m/0'/0'/0'"),
    amounts=st.lists(st.integers(min_value=1, max_value=1000), min_size=1, max_size=5, unique=True),
    unit=st.sampled_from(["sat", "usd", "eur"]),
    input_fee_ppk=st.integers(min_value=0, max_value=1000)
)
def test_fuzz_mint_keyset(seed, derivation_path, amounts, unit, input_fee_ppk):
    # Sort amounts as usually expected
    amounts.sort()
    mk = MintKeyset(
        seed=seed,
        derivation_path=derivation_path,
        amounts=amounts,
        unit=unit,
        input_fee_ppk=input_fee_ppk
    )
    assert mk.seed == seed
    assert mk.derivation_path == derivation_path
    assert mk.amounts == amounts
    assert mk.unit == Unit[unit]
    assert mk.input_fee_ppk == input_fee_ppk
    
    # Check keys generation
    assert mk.public_keys
    assert len(mk.public_keys) == len(amounts)
    assert mk.id

@given(
    id=st.text(min_size=1, max_size=12),
    unit=st.sampled_from(["sat", "usd", "eur"]),
    input_fee_ppk=st.integers(min_value=0, max_value=1000),
    public_keys_list=st.lists(public_key_strategy(), min_size=1, max_size=5)
)
def test_fuzz_wallet_keyset(id, unit, input_fee_ppk, public_keys_list):
    # Construct dict mapping amount to key
    amounts = range(1, len(public_keys_list) + 1)
    public_keys = dict(zip(amounts, public_keys_list))
    
    wk = WalletKeyset(
        id=id,
        unit=unit,
        input_fee_ppk=input_fee_ppk,
        public_keys=public_keys
    )
    
    assert wk.id == id
    assert wk.unit == Unit[unit]
    assert wk.input_fee_ppk == input_fee_ppk
    assert wk.public_keys == public_keys
    
    # Serialization
    serialized = wk.serialize()
    assert isinstance(serialized, str)

@given(
    proofs=st.lists(st.builds(Proof, id=st.text(min_size=1, max_size=10), amount=st.integers(min_value=1), secret=st.text(min_size=1), C=hex_string()), min_size=1, max_size=5),
    mint=st.text(min_size=1, max_size=50),
    memo=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
    unit=st.sampled_from(["sat", "usd", "eur"])
)
def test_fuzz_token_v3(proofs, mint, memo, unit):
    token_v3_token = TokenV3Token(mint=mint, proofs=proofs)
    token = TokenV3(token=[token_v3_token], _memo=memo, _unit=unit)
    
    assert token.mint == mint
    assert token.proofs == proofs
    assert token.memo == memo
    assert token.unit == unit
    
    # Serialization
    serialized = token.serialize()
    assert serialized.startswith("cashuA")
    
    # Deserialization
    deserialized = TokenV3.deserialize(serialized)
    # Note: Deserialized object might not be exactly equal due to list ordering or internal state,
    # but critical fields should match.
    assert deserialized.mint == mint
    assert len(deserialized.proofs) == len(proofs)
    # Check amount match
    assert deserialized.amount == token.amount

@given(
    proofs=st.lists(st.builds(Proof, id=hex_string(min_len=4, max_len=4), amount=st.integers(min_value=1), secret=st.text(min_size=1), C=hex_string()), min_size=1, max_size=5),
    mint=st.text(min_size=1, max_size=50),
    memo=st.one_of(st.none(), st.text(min_size=1, max_size=50)),
    unit=st.sampled_from(["sat", "usd", "eur"])
)
def test_fuzz_token_v4(proofs, mint, memo, unit):
    # To construct TokenV4, it's easier to go via TokenV3 and convert, or construct manually
    # Let's try converting from V3 as it tests that path too.
    # Note: TokenV4 requires keyset id (proof.id) to be hex bytes
    
    # Fix proof IDs to be valid hex for V4
    for p in proofs:
        p.id = "00" * 4 # 8 chars hex = 4 bytes
        
    token_v3_token = TokenV3Token(mint=mint, proofs=proofs)
    token_v3 = TokenV3(token=[token_v3_token], _memo=memo, _unit=unit)
    
    token_v4 = TokenV4.from_tokenv3(token_v3)
    
    assert token_v4.mint == mint
    assert token_v4.unit == unit
    assert token_v4.memo == memo
    
    # Serialization
    serialized = token_v4.serialize()
    assert serialized.startswith("cashuB")
    
    # Deserialization
    deserialized = TokenV4.deserialize(serialized)
    assert deserialized.mint == mint
    assert deserialized.amount == token_v4.amount
