# cashu

**The author is NOT a cryptographer and has not tested the libraries used or the code nor has anyone reviewed the work. This means it's very likely a fatal flaw somewhere. This is meant only as educational and is not production ready.**

Ecash implementation based on David Wagner's variant of Chaumian blinding. Token logic based on [minicash](https://github.com/phyro/minicash) ([description](https://gist.github.com/phyro/935badc682057f418842c72961cf096c)) which implements a [Blind Diffie-Hellman Key Exchange](https://cypherpunks.venona.com/date/1996/03/msg01848.html) scheme written down by Ruben Somsen [here](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406). The database mechanics and the Lightning backend uses parts from [LNbits](https://github.com/lnbits/lnbits-legend).

Big thanks to [phyro](https://github.com/phyro) for their work and further discussions and improvements.

## Install

```bash
git clone https://github.com/callebtc/cashu.git
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev python3-dev
# on mac: brew install postgres

# install python using pyenv
curl https://pyenv.run | bash

# put this in your ~/.bashrc
echo export PYENV_ROOT=\"$HOME/.pyenv\" >> ~/.bashrc
echo command -v pyenv >/dev/null || export PATH=\"$PYENV_ROOT/bin:$PATH\" >> ~/.bashrc
source ~/.bashrc
echo eval \"$(pyenv init -)\" >> ~/.bashrc
echo eval \"$(pyenv virtualenv-init -)\" >> ~/.bashrc
source ~/.bashrc
pyenv install 3.9.13

# install poetry
curl -sSL https://install.python-poetry.org | python3 -
echo export PATH=\"$HOME/.local/bin:$PATH\" >> ~/.bashrc
source ~/.bashrc

# install cashu
cd cashu
pyenv local 3.9.13
poetry install
```

### Configuration
```bash
mv .env.example .env
# edit .env file
vim .env
```

## Run mint
```bash
poetry run uvicorn mint.app:app --port 3338
```
## Run wallet

#### Request a mint

This will return a Lightning invoice and a payment hash. You have to pay the invoice before you can receive the tokens
```bash
poetry run ./cashu --wallet=wallet --mint=420
```
Returns:
```bash
Balance: 0
{'pr': 'lnbc4200n1p3jp5clsp5vcfkyqtnkcx9287auhesqwj40che77pd4ymaltc3ruazh3vcgs3qpp5qzwkavpd4pmfkdmq9trdnrk2lswkt0fypqg55h2sucx6yq9ushzsdq4vdshx6r4ypjx2ur0wd5hgxqyjw5qcqpjrzjq0qly7quwdwq2wr52et5gl65dagdgqdwgn9an58mhejnsvmmu996xzetgvqqwzcqqqqqqqqqqqqqqqqq9q9qyysgqfjwnl4za4naf7l2wwcck2gk6y9mvjt5dz9gptfkpl0j50ygkdkuxyjcy3zgd2tk4995yw8gx39cx2qwm9dgwc0t9t6hrgvjzauykqrqpgw0xx3', 'hash': '009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5'}
```

#### Mint tokens
After paying the invoice, copy the `hash` value from above and add it to the command
```bash
poetry run ./cashu --wallet=wallet --mint=420 --hash=009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5
```
You should see your balance update accordingly:
```bash
Balance: 0
Balance: 420
```

#### Send tokens
```bash
poetry run ./cashu --send=69
```
You should see the encoded tokens that you can send via text to another person. Copy them and send them via any means.
```bash
W3siYW1vdW50IjogMSwgIkMiOiB7IngiOiAzMzg0Mzg0NDYzNzAwMTY1NDA2MTQxMDY3Mzg1MDg5MjA2MTU2NjQxMjM4Nzg5MDE4NzAzODg0NjAwNDUzNTAwNzY3ODIzMjA2NzAyOSwgInkiOiA1MDE3NjAwNDA1Nzk2MDU4NDIxNTY4NzUyOTU0MTYwNDEyOTM1MzMwMTQ3MDk3ODMyMjExNzI1NTUyODM4MTY4NDAzMzE5MDgzNjE0MX0sICJzZWNyZXQiOiAiMjc4MDM0ODcwNjExNzAzOTQxODE2MDk1MTgzNTI3Njg4NjY1MzY2In0sIHsiYW1vdW50IjogNCwgIkMiOiB7IngiOiA3NzI5OTU2MTY4NDQ5NzAyMjUwMjQ1MjE0MzMzODEyNDY3MTE4NzAwNTMyNjI1MjExMzM5MzY0MzA3Mjc1MTE4NDQ2MTE0ODMxMTUyMywgInkiOiAxMDE2OTk5MjIyMTI4ODQ0NDM5MDI0NjA3MDcxMDg3MzYzMjA5Mjk1NzI5NDAwNTU1Njg4NDg5NDEzMDI5MzE5MDY4NTU0NjY4MzkzNzB9LCAic2VjcmV0IjogIjExNDQ0MzY1NDkwMjExMjk4NDI0MDAwODI3MDgwNDQ3NzIzMzI1NCJ9LCB7ImFtb3VudCI6IDY0LCAiQyI6IHsieCI6IDk1MDA5NDg4OTA0MDk5MDY3ODk5NzY4NDI3OTEyNzcxMzg0MDc2OTQxOTQ3MTg5NTQ5ODE4NjMwMDE0MjA0MjUxMzkyNTU4NTA5MDksICJ5IjogMzQ0MTQ4OTg3NjM3MTkzMDk0NjU2MjU5Mzk0MzU5NTc3NzQ0MzQ4NTY3MDg2MDQzNzc4NjY5NDE1OTg5OTI5NDQwNTkxNDU4OTA3NjV9LCAic2VjcmV0IjogIjE5MTg4ODU3MjMwODU5NjgyODc5MTgzMTQwNzc2OTgzNDc4NzE5NyJ9XQ
```

#### Receive tokens
To receive tokens, another user enters:
```bash
poetry run ./cashu --receive=W3siYW1vdW50IjogMSwgIkMiOi...
```
Returns:
```bash
wallet balance: 0
wallet balance: 69
```

#### Invalidate tokens
The sending user needs to invalidate their tokens from above, otherwise they will try to double spend them (which won't work because the server keeps a list of all spent tokens):
```bash
poetry run ./cashu --invalidate=W3siYW1vdW50IjogMSwgIkMiOi...
```
Returns:
```bash
wallet balance: 420
wallet balance: 351
```


## Test instance
*Warning: this instance is just for demonstration only. Currently, only Lightning deposits work but not withdrawals. The server could vanish at any moment so consider any Satoshis you deposit a donation.*

Change the appropriate `.env` file settings to
```bash
MINT_HOST=8333.space
MINT_PORT=3338
```

## Screenshot
![screenshot](https://user-images.githubusercontent.com/93376500/189533335-68a863e2-bacd-47c1-aecc-e4fb09883d11.jpg)
