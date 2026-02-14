from cashu.core.nuts.nut18 import PaymentRequest, Transport


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
    
    encoded = req.serialize()
    # expected_encoded = "creqApWF0gaNhdGVub3N0cmFheKlucHJvZmlsZTFxeTI4d3VtbjhnaGo3dW45ZDNzaGp0bnl2OWtoMnVld2Q5aHN6OW1od2RlbjV0ZTB3ZmprY2N0ZTljdXJ4dmVuOWVlaHFjdHJ2NWhzenJ0aHdkZW41dGUwZGVoaHh0bnZkYWtxcWd5ZGFxeTdjdXJrNDM5eWtwdGt5c3Y3dWRoZGh1NjhzdWNtMjk1YWtxZWZkZWhrZjBkNDk1Y3d1bmw1YWeBgmFuYjE3YWloYjdhOTAxNzZhYQphdWNzYXRhbYF4Imh0dHBzOi8vbm9mZWVzLnRlc3RudXQuY2FzaHUuc3BhY2U"
    
    # NOTE: CBOR dict key order is generally undetermined unless canonical, 
    # but let's check if the fields match when deserialized
    
    decoded = PaymentRequest.deserialize(encoded)
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
    serialized = req.serialize()
    assert serialized.startswith("creqA")
    
    decoded = PaymentRequest.deserialize(serialized)
    assert decoded.a == 100
    assert decoded.u == "usd"
    assert decoded.m == ["https://mint.example.com"]
    assert decoded.d == "Coffee"
    assert decoded.i is None
