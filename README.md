# Cashu Nutshell

**Cashu is a Chaumian Ecash wallet and mint for Bitcoin Lightning. Cashu Nutshell is the reference implementation in Python.**

<a href="https://pypi.org/project/cashu/"><img alt="Release" src="https://img.shields.io/pypi/v/cashu?color=black"></a> <a href="https://pepy.tech/project/cashu"> <img alt="Downloads" src="https://pepy.tech/badge/cashu"></a> <a href="https://app.codecov.io/gh/cashubtc/cashu"><img alt="Coverage" src="https://img.shields.io/codecov/c/gh/cashubtc/cashu"></a>


*Disclaimer: The author is NOT a cryptographer and this work has not been reviewed. This means that there is very likely a fatal flaw somewhere. Cashu is still experimental and not production-ready.*

Cashu is an Ecash implementation based on David Wagner's variant of Chaumian blinding ([protocol specs](https://github.com/cashubtc/nuts)). Token logic based on [minicash](https://github.com/phyro/minicash) ([description](https://gist.github.com/phyro/935badc682057f418842c72961cf096c)) which implements a [Blind Diffie-Hellman Key Exchange](https://cypherpunks.venona.com/date/1996/03/msg01848.html) scheme written down [here](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406). The database mechanics in Cashu Nutshell and the Lightning backend uses parts from [LNbits](https://github.com/lnbits/lnbits-legend).

<p align="center">
<a href="#cashu-client-protocol">Cashu protocol</a> ·
<a href="#easy-install">Quick Install</a> ·
<a href="#hard-install-poetry">Manual install</a> ·
<a href="#configuration">Configuration</a> ·
<a href="#using-cashu">Using Cashu</a> ·
<a href="#running-a-mint">Run a mint</a>
</p>

### Feature overview of Nutshell

- Full Bitcoin Lightning support
- CLI Cashu wallet and mint server
- Include the wallet and mint library into other Python projects
- PostgreSQL and SQLite database support
- Wallet: Builtin Tor for hiding IPs
- Wallet: Multimint support
- Wallet: Send and receive tokens on nostr

## The Cashu protocol
There are ongoing efforts to implement alternative Cashu clients that use the same protocol. See the [documentation page](https://docs.cashu.space/) for more information on other projects. If you are interested in helping with Cashu development, please refer to the protocol specs [protocol specs](https://github.com/cashubtc/nuts). 

## Easy Install

The easiest way to use Cashu is to install the package it via pip:
```bash
pip install cashu
```

To update Cashu, use `pip install cashu -U`. 

If you have problems running the command above on Ubuntu, run `sudo apt install -y pip pkg-config` and `pip install wheel`. On macOS, you might have to run `pip install wheel` and `brew install pkg-config`.

You can skip the entire next section about Poetry and jump right to [Using Cashu](#using-cashu).

## Hard install: Poetry
These steps help you install Python via pyenv and Poetry. If you already have Poetry running on your computer, you can skip this step and jump right to [Install Cashu](#poetry-install-cashu).

#### Poetry: Prerequisites

```bash
# on ubuntu:
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev python3-dev libsqlite3-dev ncurses-dev libbz2-dev libreadline-dev lzma-dev

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
git clone https://github.com/callebtc/cashu.git --recurse-submodules
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
*Warning: this instance is just for demonstration only. The server could vanish at any moment so consider any Satoshis you deposit a donation.*

Change the appropriate `.env` file settings to
```bash
MINT_URL=https://8333.space:3338
```

# Using Cashu
```bash
cashu info
```

Returns:
```bash
Version: 0.12.1
Debug: False
Cashu dir: /home/user/.cashu
Wallet: wallet
Mint URL: https://8333.space:3338
```

#### Check balance
```bash
cashu balance
```

#### Generate a Lightning invoice 

This command will return a Lightning invoice that you need to pay to mint new ecash tokens.

```bash
cashu invoice 420
```

The client will check every few seconds if the invoice has been paid. If you abort this step but still pay the invoice, you can use the command `cashu invoice <amount> --hash <hash>`.

#### Pay a Lightning invoice
```bash
cashu pay lnbc120n1p3jfmdapp5r9jz...
```

#### Send tokens
To send tokens to another user, enter
```bash
cashu send 69
```
You should see the encoded token. Copy the token and send it to another user such as via email or a messenger. The token looks like this:
```bash
eyJwcm9vZnMiOiBbey...
```

You can now see that your available balance has dropped by the amount that you reserved for sending if you enter `cashu balance`:
```bash
Balance: 420 sat
```

#### Receive tokens
To receive tokens, another user enters:
```bash
cashu receive eyJwcm9vZnMiOiBbey...
```
You should see the balance increase:
```bash
Balance: 0 sat
Balance: 69 sat
```

# Starting the wallet API daemon
Nutshell wallet can be used in daemon mode that can be controlled through a REST API:
```bash
cashu -d
```

You can find the API docs at [http://localhost:4448/docs](http://localhost:4448/docs).

# Running a mint
This command runs the mint on your local computer. Skip this step if you want to use the [public test mint](#test-instance) instead.
```bash
python -m cashu.mint
```

You can turn off Lightning support and mint as many tokens as you like by setting `LIGHTNING=FALSE` in the `.env` file.


# Running tests
To run the tests in this repository, first install the dev dependencies with 
```bash
poetry install --with dev
```

Then, make sure to set up your `.env` file to use your local mint and disable Lightning and Tor:
```bash
LIGHTNING=FALSE
TOR=FALSE
```
You can run the tests with
```bash
poetry run pytest tests
```
