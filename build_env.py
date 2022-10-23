import os
from pathlib import Path
import requests

LNBITS_ENDPOINT = "Not found"
LNBITS_ENDPOINT_LOCAL = "http://127.0.0.1:5001"
LNBITS_ENDPOINT_DOCKER = "http://lnbits:5001"
ENV_FILE = os.path.join(str(Path.home()), ".cashu", ".env")

print("Creating wallet and fetching admin key")

res = None
try:
    res = requests.get(f"{LNBITS_ENDPOINT_LOCAL}/wallet?nme=12345678")
    LNBITS_ENDPOINT = LNBITS_ENDPOINT_LOCAL
except:
    pass

if res is None:
    try:
        res = requests.get(f"{LNBITS_ENDPOINT_DOCKER}/wallet?nme=12345678")
        LNBITS_ENDPOINT = LNBITS_ENDPOINT_DOCKER
    except:
        pass

if res is None:
    raise Exception("Could not connect to lnbits")

admin_key = res.text.split('adminkey": "')[1].split('", "balance_msat"')[0]
user = res.text.split('"user": "')[1].split('"}]};')[0]

print(f"Admin key: {admin_key}")
print(f"User id: {user}")

e = open(ENV_FILE, "w")
e.write(f"LNBITS_ENDPOINT={LNBITS_ENDPOINT}\n")
e.write(f"LNBITS_KEY={admin_key}\n")
e.write(f"# user={user}")
e.close()

print("wrote .env file")
