from cashu.wallet.api import app as wallet_api
from fastapi import FastAPI

# add the api to the main app
app = FastAPI()
app.include_router(wallet_api, tags=["wallet"])
