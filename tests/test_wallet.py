import time
from re import S

from cashu.core.helpers import async_unwrap
from cashu.core.migrations import migrate_databases
from cashu.wallet import migrations
from cashu.wallet.wallet import Wallet as Wallet1
from cashu.wallet.wallet import Wallet as Wallet2

SERVER_ENDPOINT = "http://localhost:3338"


async def assert_err(f, msg):
    """Compute f() and expect an error message 'msg'."""
    try:
        await f
    except Exception as exc:
        assert exc.args[0] == msg, Exception(
            f"Expected error: {msg}, got: {exc.args[0]}"
        )


def assert_amt(proofs, expected):
    """Assert amounts the proofs contain."""
    assert [p["amount"] for p in proofs] == expected


async def run_test():
    wallet1 = Wallet1(SERVER_ENDPOINT, "data/wallet1", "wallet1")
    await migrate_databases(wallet1.db, migrations)
    wallet1.load_mint()
    wallet1.status()

    wallet2 = Wallet2(SERVER_ENDPOINT, "data/wallet2", "wallet2")
    await migrate_databases(wallet2.db, migrations)
    wallet2.load_mint()
    wallet2.status()

    proofs = []

    # Mint a proof of promise. We obtain a proof for 64 coins
    proofs += await wallet1.mint(64)
    print(proofs)
    assert wallet1.balance == 64
    wallet1.status()

    # Mint an odd amount (not in 2^n)
    proofs += await wallet1.mint(63)
    assert wallet1.balance == 64 + 63

    w1_fst_proofs, w1_snd_proofs = await wallet1.split(wallet1.proofs, 65)
    assert wallet1.balance == 63 + 64
    wallet1.status()

    # Error: We try to double-spend by providing a valid proof twice
    await assert_err(
        wallet1.split(wallet1.proofs + proofs, 20),
        f"Mint Error: tokens already spent. Secret: {proofs[0]['secret']}",
    )
    assert wallet1.balance == 63 + 64
    wallet1.status()

    w1_fst_proofs, w1_snd_proofs = await wallet1.split(wallet1.proofs, 20)
    # we expect 44 and 20 -> [4, 8, 32], [4, 16]
    print(w1_fst_proofs)
    print(w1_snd_proofs)
    # assert [p["amount"] for p in w1_fst_proofs] == [4, 8, 32]
    assert [p["amount"] for p in w1_snd_proofs] == [4, 16]
    assert wallet1.balance == 63 + 64
    wallet1.status()

    # Error: We try to double-spend and it fails
    await assert_err(
        wallet1.split([proofs[0]], 10),
        f"Mint Error: tokens already spent. Secret: {proofs[0]['secret']}",
    )

    assert wallet1.balance == 63 + 64
    wallet1.status()

    # Redeem the tokens in wallet2
    w2_fst_proofs, w2_snd_proofs = await wallet2.redeem(w1_snd_proofs)
    print(w2_fst_proofs)
    print(w2_snd_proofs)
    assert wallet1.balance == 63 + 64
    assert wallet2.balance == 20
    wallet2.status()

    # wallet1 invalidates his proofs
    await wallet1.invalidate(w1_snd_proofs)
    assert wallet1.balance == 63 + 64 - 20
    wallet1.status()

    w1_fst_proofs2, w1_snd_proofs2 = await wallet1.split(w1_fst_proofs, 5)
    # we expect 15 and 5 -> [1, 2, 4, 8], [1, 4]
    print(w1_fst_proofs2)
    print(w1_snd_proofs2)
    assert wallet1.balance == 63 + 64 - 20
    wallet1.status()

    # Error: We try to double-spend and it fails
    await assert_err(
        wallet1.split(w1_snd_proofs, 5),
        f"Mint Error: tokens already spent. Secret: {w1_snd_proofs[0]['secret']}",
    )

    assert wallet1.balance == 63 + 64 - 20
    wallet1.status()

    assert wallet1.proof_amounts() == [1, 2, 4, 4, 32, 64]
    assert wallet2.proof_amounts() == [4, 16]

    # manipulate the proof amount
    # w1_fst_proofs2_manipulated = w1_fst_proofs2.copy()
    # w1_fst_proofs2_manipulated[0]["amount"] = 123
    # await assert_err(
    #     wallet1.split(w1_fst_proofs2_manipulated, 20),
    #     "Error: 123",
    # )

    # try to split an invalid amount
    await assert_err(
        wallet1.split(w1_snd_proofs, -500),
        "Mint Error: invalid split amount: -500",
    )

    # mint with secrets
    secret = f"asdasd_{time.time()}"
    w1_fst_proofs, w1_snd_proofs = await wallet1.split(
        wallet1.proofs, 65, snd_secret=secret
    )

    # p2sh test
    p2shscript = await wallet2.create_p2sh_lock()
    txin_p2sh_address = p2shscript.address
    lock = f"P2SH:{txin_p2sh_address}"
    _, send_proofs = await wallet1.split_to_send(wallet1.proofs, 8, lock)
    _, _ = await wallet2.redeem(
        send_proofs, snd_script=p2shscript.script, snd_siganture=p2shscript.signature
    )

    # strip away the secrets
    w1_snd_proofs_manipulated = w1_snd_proofs.copy()
    for p in w1_snd_proofs_manipulated:
        p.secret = ""
    await assert_err(
        wallet2.redeem(w1_snd_proofs_manipulated),
        "Mint Error: no secret in proof.",
    )


if __name__ == "__main__":
    async_unwrap(run_test())


def test():
    async_unwrap(run_test())
