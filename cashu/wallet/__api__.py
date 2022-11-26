import logging
from fastapi import FastAPI
from cashu.wallet.api import app as wallet_api

# add the api to the main app
app = FastAPI()
app.include_router(wallet_api, tags=["wallet"])
logging.basicConfig(format="%(asctime)s\t%(levelname)s\t%(name)s %(lineno)d -- %(message)s", level=logging.INFO)
