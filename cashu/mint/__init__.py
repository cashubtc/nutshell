from cashu.core.settings import MINT_PRIVATE_KEY
from cashu.mint.ledger import Ledger

print("init")

ledger = Ledger(MINT_PRIVATE_KEY, "data/mint")
