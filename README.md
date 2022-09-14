# cashu

**The author is NOT a cryptographer and has not tested the libraries used or the code nor has anyone reviewed the work. This means it's very likely a fatal flaw somewhere. This is meant only as educational and is not production ready.**

Ecash implementation based on David Wagner's variant of Chaumian blinding. Token logic based on [minicash](https://github.com/phyro/minicash) ([description](https://gist.github.com/phyro/935badc682057f418842c72961cf096c)) which implements a [Blind Diffie-Hellman Key Exchange](https://cypherpunks.venona.com/date/1996/03/msg01848.html) scheme written down by Ruben Somsen [here](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406). The database mechanics and the Lightning backend uses parts from [LNbits](https://github.com/lnbits/lnbits-legend).

Big thanks to [phyro](https://github.com/phyro) for their work and further discussions and improvements.

## Install
### Prerequisites
```bash
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev python3-dev
# on mac: brew install postgres

# install python using pyenv
curl https://pyenv.run | bash

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
```
### Install Cashu
```bash
# install cashu
git clone https://github.com/callebtc/cashu.git
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

To use the wallet with the [public test mint](#test-instance), you need to change the appropriate entries in the `.env` file. 

## Run a mint yourself
This runs the mint on your local computer. Skip this step if you want to use the [public test mint](#test-instance) instead.
```bash
poetry run mint
```

## Use wallet

#### Request a mint

This command will return a Lightning invoice and a payment hash. You have to pay the invoice before you can receive the tokens. Note: Minting tokens involves two steps: requesting a mint, and actually minting tokens (see below).

```bash
poetry run cashu mint 420
```
Returns:
```bash
Balance: 0
{
    'pr': 'lnbc4200n1p3jp5clsp5vcfkyqtnkcx9287auhesqwj40che77pd4ymaltc3ruazh3vcgs3qpp5qzwkavpd4pmfkdmq9trdnrk2lswkt0fypqg55h2sucx6yq9ushzsdq4vdshx6r4ypjx2ur0wd5hgxqyjw5qcqpjrzjq0qly7quwdwq2wr52et5gl65dagdgqdwgn9an58mhejnsvmmu996xzetgvqqwzcqqqqqqqqqqqqqqqqq9q9qyysgqfjwnl4za4naf7l2wwcck2gk6y9mvjt5dz9gptfkpl0j50ygkdkuxyjcy3zgd2tk4995yw8gx39cx2qwm9dgwc0t9t6hrgvjzauykqrqpgw0xx3', 
    'hash': '009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5'
}
```

#### Mint tokens
After paying the invoice, copy the `hash` value from above and add it to the command
```bash
poetry run cashu mint 420 --hash=009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5
```
You should see your balance update accordingly:
```bash
Balance: 0
Balance: 420
```

#### Send tokens
To send tokens to another user, enter
```bash
poetry run cashu send 69
```
You should see the encoded token. Copy the token and send it to another user such as via email or a messenger. The token looks like this:
```bash
W3siYW1vdW50IjogMSwgIkMiOiB7IngiOiAzMzg0Mzg0NDYzNzAwMTY1NDA2MTQxMDY3Mzg1MDg5MjA2MTU2NjQxMjM4Nzg5MDE4NzAzODg0NjAwNDUzNTAwNzY3...
```

#### Receive tokens
To receive tokens, another user enters:
```bash
poetry run cashu receive W3siYW1vdW50IjogMSwgIkMiOi...
```
You should see the balance increase:
```bash
wallet balance: 0
wallet balance: 69
```

#### Burn tokens
The sending user needs to burn (invalidate) their tokens from above, otherwise they will try to double spend them (which won't work because the server keeps a list of all spent tokens):
```bash
poetry run cashu burn W3siYW1vdW50IjogMSwgIkMiOi...
```
Returns:
```bash
wallet balance: 420
wallet balance: 351
```


## Test instance
*Warning: this instance is just for demonstration only. Currently, only Lightning deposits work but not withdrawals. The server could vanish at any moment so consider any Satoshis you deposit a donation. I will add Lightning withdrawals soon so unless someone comes up with a huge inflation bug, you might be able to claim them back at a later point in time.*


Change the appropriate `.env` file settings to
```bash
MINT_HOST=8333.space
MINT_PORT=3338
```

## Screenshot
![screenshot](https://user-images.githubusercontent.com/93376500/189533335-68a863e2-bacd-47c1-aecc-e4fb09883d11.jpg)
