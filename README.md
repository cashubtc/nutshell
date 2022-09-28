# cashu

**Cashu is a Chaumian Ecash wallet and mint with Bitcoin Lightning support.**

*Disclaimer: The author is NOT a cryptographer and this work has not been reviewed. This means that there is very likely a fatal flaw somewhere. Cashu is still experimental and not production-ready.*

Cashu is an Ecash implementation based on David Wagner's variant of Chaumian blinding. Token logic based on [minicash](https://github.com/phyro/minicash) ([description](https://gist.github.com/phyro/935badc682057f418842c72961cf096c)) which implements a [Blind Diffie-Hellman Key Exchange](https://cypherpunks.venona.com/date/1996/03/msg01848.html) scheme written down by Ruben Somsen [here](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406). The database mechanics and the Lightning backend uses parts from [LNbits](https://github.com/lnbits/lnbits-legend).

<p align="center">
Quick links:
<a href="#cashu-client-protocol">Cashu client protocol</a> ·
<a href="#easy-install">Quick Install</a> ·
<a href="#hard-install-poetry">Manual install</a> ·
<a href="#configuration">Configuration</a> ·
<a href="#using-cashu">Using Cashu</a> ·
<a href="#running-a-mint">Run a mint</a>
<br><br>    
</p>

## Cashu client protocol
There are ongoing efforts to implement alternative Cashu clients that use the same protocol such as a [Cashu Javascript wallet](https://github.com/motorina0/cashu-js-wallet). If you are interested in helping with Cashu development, please see the [docs](docs/) for the notation and conventions used. 

## Easy Install

The easiest way to use Cashu is to install the package it via pip:
```bash
pip install cashu
```

To update Cashu, use `pip install cashu -U`. If you have problems running the command above on Ubuntu, run `sudo apt install -y pip pkg-config libpq-dev`. On macOS, run `brew install postgresql`.

You can skip the entire next section about Poetry and jump right to [Using Cashu](#using-cashu).

## Hard install: Poetry
These steps help you install Python via pyenv and Poetry. If you already have Poetry running on your computer, you can skip this step and jump right to [Install Cashu](#poetry-install-cashu).

#### Poetry: Prerequisites

```bash
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev python3-dev
# on mac: brew install postgres

# install python using pyenv
curl https://pyenv.run | bash

# !! follow the instructions of pyenv init to setup pyenv !!
pyenv init

# restart your shell (or source your .rc file), then install python:
pyenv install 3.9.13

# install poetry
curl -sSL https://install.python-poetry.org | python3 -
echo export PATH=\"$HOME/.local/bin:$PATH\" >> ~/.bashrc
source ~/.bashrc
```
#### Poetry: Install Cashu
```bash
# install cashu
git clone https://github.com/callebtc/cashu.git
cd cashu
pyenv local 3.9.13
poetry install
```

#### Poetry: Update Cashu
To update Cashu to the newest version enter
```bash
git pull && poetry install
```
#### Poetry: Using Cashu

Cashu should be now installed. To execute the following commands, activate your virtual Poetry environment via

```bash
poetry shell
```

If you don't activate your environment, just prepend `poetry run` to all following commands.
## Configuration
```bash
mv .env.example .env
# edit .env file
vim .env
```

To use the wallet with the [public test mint](#test-instance), you need to change the appropriate entries in the `.env` file. 

#### Test instance
*Warning: this instance is just for demonstration only. Currently, only Lightning deposits work but not withdrawals. The server could vanish at any moment so consider any Satoshis you deposit a donation. I will add Lightning withdrawals soon so unless someone comes up with a huge inflation bug, you might be able to claim them back at a later point in time.*


Change the appropriate `.env` file settings to
```bash
MINT_HOST=8333.space
MINT_PORT=3338
```

# Using Cashu

#### Request a mint

This command will return a Lightning invoice and a payment hash. You have to pay the invoice before you can receive the tokens. Note: Minting tokens involves two steps: requesting a mint, and actually minting tokens (see below).

```bash
cashu mint 420
```
Returns:
```bash
Balance: 0 sat (Available: 0 sat in 0 tokens)
{
    'pr': 'lnbc4200n1p3jp5clsp5vcfkyqtnkcx9287auhesqwj40che77pd4ymaltc3ruazh3vcgs3qpp5qzwkavpd4pmfkdmq9trdnrk2lswkt0fypqg55h2sucx6yq9ushzsdq4vdshx6r4ypjx2ur0wd5hgxqyjw5qcqpjrzjq0qly7quwdwq2wr52et5gl65dagdgqdwgn9an58mhejnsvmmu996xzetgvqqwzcqqqqqqqqqqqqqqqqq9q9qyysgqfjwnl4za4naf7l2wwcck2gk6y9mvjt5dz9gptfkpl0j50ygkdkuxyjcy3zgd2tk4995yw8gx39cx2qwm9dgwc0t9t6hrgvjzauykqrqpgw0xx3', 
    'hash': '009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5'
}
```

#### Mint tokens
After paying the invoice, copy the `hash` value from above and add it to the command
```bash
cashu mint 420 --hash=009d6eb02da8769b37602ac6d98ecafc1d65bd2408114a5d50e60da200bc85c5
```
You should see your balance update accordingly:
```bash
Balance: 0 sat (Available: 0 sat in 0 tokens)
Balance: 420 sat (Available: 420 sat in 4 tokens)
```

Available tokens here means those tokens that have not been reserved for sending.

#### Check balance
```bash
cashu balance
```

#### Send tokens
To send tokens to another user, enter
```bash
cashu send 69
```
You should see the encoded token. Copy the token and send it to another user such as via email or a messenger. The token looks like this:
```bash
W3siYW1vdW50IjogMSwgIkMiOiB7IngiOiAzMzg0Mzg0NDYzNzAwMTY1NDA2MTQxMDY3Mzg1MDg5MjA2MTU2NjQxMjM4Nzg5MDE4NzAzODg0NjAwNDUzNTAwNzY3...
```

You can now see that your available balance has dropped by the amount that you reserved for sending if you enter `cashu balance`:
```bash
Balance: 420 sat (Available: 351 sat in 7 tokens)
```

#### Receive tokens
To receive tokens, another user enters:
```bash
cashu receive W3siYW1vdW50IjogMSwgIkMiOi...
```
You should see the balance increase:
```bash
Balance: 0 sat (Available: 0 sat in 0 tokens)
Balance: 69 sat (Available: 69 sat in 3 tokens)
```

#### Burn tokens
The sending user needs to burn (invalidate) their tokens from above, otherwise they will try to double spend them (which won't work because the server keeps a list of all spent tokens):
```bash
cashu burn W3siYW1vdW50IjogMSwgIkMiOi...
```
Returns:
```bash
Balance: 420 sat (Available: 351 sat in 7 tokens)
Balance: 351 sat (Available: 351 sat in 7 tokens)
```

#### Pay a Lightning invoice
```bash
cashu pay lnbc120n1p3jfmdapp5r9jz...
```
Returns:
```bash
Balance: 351 sat (Available: 351 sat in 7 tokens)
Balance: 339 sat (Available: 339 sat in 8 tokens)
```

# Running a mint
This command runs the mint on your local computer. Skip this step if you want to use the [public test mint](#test-instance) instead.
```bash
mint
```

You can turn off Lightning support and mint as many tokens as you like by setting `LIGHTNING=FALSE` in the `.env` file.

