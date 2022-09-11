# cashu

## Install

```bash
https://github.com/callebtc/cashu.git
sudo apt install pkg-config libffi-dev libpq-dev
# on mac: brew install postgres
curl https://pyenv.run | bash
pyenv install 3.9.13
cd cashu
mkdir data/wallet data/mint
poetry install
```

## Run mint
```bash
cd mint/
poetry run flask run --host 0.0.0.0 --port 3338
```
## Run wallet

```bash
poetry run ./cashu --wallet=wallet --mint=420
```