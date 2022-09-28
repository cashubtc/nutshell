from core.settings import MINT_PRIVATE_KEY
from mint.ledger import Ledger

print("init")

ledger = Ledger(MINT_PRIVATE_KEY, "data/mint")
