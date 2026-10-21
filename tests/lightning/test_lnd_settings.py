from cashu.core.settings import LndRestFundingSource, LndRPCFundingSource


def test_lnd_allow_self_payment_defaults_to_false():
    rest = LndRestFundingSource(_env_file=None)
    rpc = LndRPCFundingSource(_env_file=None)
    assert rest.mint_lnd_allow_self_payment is False
    assert rpc.mint_lnd_allow_self_payment is False


def test_lnd_allow_self_payment_reads_env(monkeypatch):
    monkeypatch.setenv("MINT_LND_ALLOW_SELF_PAYMENT", "true")
    rest = LndRestFundingSource(_env_file=None)
    rpc = LndRPCFundingSource(_env_file=None)
    assert rest.mint_lnd_allow_self_payment is True
    assert rpc.mint_lnd_allow_self_payment is True
