import asyncio

import cashu.core.bolt11 as bolt11
from cashu.wallet.lightning import LightningWallet


async def main():
    # wallet = LightningWallet("http://localhost:3338", "data/lightning.db")
    # await wallet.async_init("http://localhost:3338", "data/lightning.db")
    wallet = await LightningWallet().async_init(
        url="http://localhost:3338", db="data/lightning.db"
    )
    print("balance", await wallet.get_balance())
    invoice = await wallet.create_invoice(1000, "test incoming")
    print("balance", await wallet.get_balance())

    print(invoice)
    # return
    assert invoice.payment_hash
    print("balance", await wallet.get_balance())
    state = ""
    while state != "paid":
        state = await wallet.get_invoice_status(invoice.payment_hash)
        await asyncio.sleep(1)
    print("balance", await wallet.get_balance())

    invoice2 = await wallet.create_invoice(10, "test outgoing")
    pr = invoice2.bolt11
    invoice_obj = bolt11.decode(pr)
    print("paying invoice", pr)

    print("creating task")
    asyncio.create_task(wallet.pay_invoice(pr=pr))
    print("task created")

    await asyncio.sleep(2)
    state = ""
    while not state.startswith("paid"):
        print("checking state")
        print("balance", await wallet.get_balance())
        print("calling wallet.get_payment_status")
        state = await wallet.get_payment_status(invoice_obj.payment_hash)
        print(state)
        await asyncio.sleep(1)


if __name__ == "__main__":
    asyncio.run(main())
