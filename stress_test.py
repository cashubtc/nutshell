import asyncio
import os
import random
import shutil
import tempfile

from cashu.wallet.wallet import Wallet


async def run_wallet_ops(wallet_id: int, mint_url: str):
    # Use different temporary locations for each wallet
    temp_dir = tempfile.mkdtemp(prefix=f"cashu_test_wallet_{wallet_id}_")
    db_path = os.path.join(temp_dir, "wallet")
    
    try:
        wallet = await Wallet.with_db(
            url=mint_url,
            db=db_path,
            name=f"wallet_{wallet_id}"
        )
        await wallet.load_mint()
        
        print(f"[{wallet_id}] Wallet initialized at {temp_dir}")
        
        # Run some basic cashu operations
        for i in range(10): 
            print(f"[{wallet_id}] Iteration {i}: Invoicing 100 sats...")
            try:
                # 1. Create invoice & Mint
                invoice = await wallet.request_mint(100)
                await wallet.mint(100, quote_id=invoice.quote)
                
                # 2. Self pay: send and receive
                keep_proofs, send_proofs = await wallet.swap_to_send(wallet.proofs, 50, set_reserved=True)
                # simulate receiving by redeeming to own wallet
                await wallet.redeem(send_proofs)

                print(f"[{wallet_id}] Iteration {i}: Self-paid. Balance: {wallet.available_balance}")
            except Exception as e:
                print(f"[{wallet_id}] Error in iteration {i}: {e}")
                
            await asyncio.sleep(random.uniform(0.01, 0.2))
            
    finally:
        shutil.rmtree(temp_dir)
        print(f"[{wallet_id}] Cleaned up {temp_dir}")

async def main():
    mint_url = "http://127.0.0.1:3338"
    num_wallets = 30
    print(f"Starting {num_wallets} wallets...")
    tasks = []
    for i in range(num_wallets):
        tasks.append(asyncio.create_task(run_wallet_ops(i, mint_url)))
        
    await asyncio.gather(*tasks)
    print("All wallets finished!")

if __name__ == "__main__":
    asyncio.run(main())
