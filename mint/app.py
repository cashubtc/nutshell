import hashlib

from ecc.curve import secp256k1, Point
from flask import Flask, request
import os
import asyncio

from mint.ledger import Ledger
from mint.migrations import m001_initial

# Ledger pubkey
ledger = Ledger("supersecretprivatekey", "../data/mint")


class MyFlaskApp(Flask):
    """
    We overload the Flask class so we can run a startup script (migration).
    Stupid Flask.
    """

    def __init__(self, *args, **kwargs):
        async def create_tasks_func():
            await asyncio.wait([m001_initial(ledger.db)])
            await ledger.load_used_proofs()
            print("Mint started.")

        loop = asyncio.get_event_loop()
        loop.run_until_complete(create_tasks_func())
        loop.close()

        return super().__init__(*args, **kwargs)

    def run(self, *args, **options):
        super(MyFlaskApp, self).run(*args, **options)


app = MyFlaskApp(__name__)


@app.route("/keys")
def keys():
    return ledger.get_pubkeys()


@app.route("/mint", methods=["POST"])
async def mint():
    amount = int(request.args.get("amount")) or 64
    x = int(request.json["x"])
    y = int(request.json["y"])
    B_ = Point(x, y, secp256k1)
    try:
        promise = await ledger.mint(B_, amount)
        return promise
    except Exception as exc:
        return {"error": str(exc)}


@app.route("/split", methods=["POST"])
async def split():
    proofs = request.json["proofs"]
    amount = request.json["amount"]
    output_data = request.json["output_data"]
    try:
        fst_promises, snd_promises = await ledger.split(proofs, amount, output_data)
        return {"fst": fst_promises, "snd": snd_promises}
    except Exception as exc:
        return {"error": str(exc)}
