import asyncio

from cashu.wallet.lightning import LightningWallet


async def main():
    # wallet = LightningWallet("http://localhost:3338", "data/lightning.db")
    # await wallet.async_init("http://localhost:3338", "data/lightning.db")
    wallet = await LightningWallet().async_init(
        url="http://localhost:3338", db="data/lightning.db"
    )
    print(await wallet.get_balance())
    invoice = await wallet.create_invoice(1000, "test")
    print(await wallet.get_balance())

    print(invoice)
    return
    assert invoice.payment_hash
    print(await wallet.get_balance())
    for i in range(10):
        print(await wallet.get_invoice_status(invoice.payment_hash))
        await asyncio.sleep(1)
    print(await wallet.get_balance())


if __name__ == "__main__":
    asyncio.run(main())
