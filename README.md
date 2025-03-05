# Cashu Nutshell

**Nutshell is a Chaumian Ecash wallet and mint for Bitcoin Lightning based on the Cashu protocol.**

<a href="https://pypi.org/project/cashu/"><img alt="Release" src="https://img.shields.io/pypi/v/cashu?color=black"></a> <a href="https://pepy.tech/project/cashu"> <img alt="Downloads" src="https://pepy.tech/badge/cashu"></a> <a href="https://app.codecov.io/gh/cashubtc/nutshell"><img alt="Coverage" src="https://img.shields.io/codecov/c/gh/cashubtc/nutshell"></a>


*Disclaimer: The author is NOT a cryptographer and this work has not been reviewed. This means that there is very likely a fatal flaw somewhere. Cashu is still experimental and not production-ready.*

Cashu is a free and open-source [Ecash protocol](https://github.com/cashubtc/nuts) based on David Wagner's variant of Chaumian blinding called [Blind Diffie-Hellman Key Exchange](https://cypherpunks.venona.com/date/1996/03/msg01848.html) scheme written down [here](https://gist.github.com/RubenSomsen/be7a4760dd4596d06963d67baf140406).

<p align="center">
<a href="#the-cashu-protocol">Cashu protocol</a> ·
<a href="#easy-install">Quick Install</a> ·
<a href="#manual-install-poetry">Manual install</a> ·
<a href="#configuration">Configuration</a> ·
<a href="#using-cashu">Using Cashu</a> ·
<a href="#running-a-mint">Run a mint</a>
</p>

### Feature overview

- Bitcoin Lightning support (LND, CLN, et al.)
- Full support for the Cashu protocol [specifications](https://github.com/cashubtc/nuts)
- Standalone CLI  wallet and mint server
- Wallet and mint library you can include in other Python projects
- PostgreSQL and SQLite
- Wallet with builtin Tor
- Use multiple mints in a single wallet

### Advanced features
- Deterministic wallet with seed phrase backup ([NUT-13](https://github.com/cashubtc/nuts/blob/main/13.md))
- Programmable ecash: P2PK and HTLCs ([NUT-10](https://github.com/cashubtc/nuts/blob/main/10.md))
- Wallet and mint support for keyset rotations
- DLEQ proofs for offline transactions ([NUT-12](https://github.com/cashubtc/nuts/blob/main/12.md))
- Send and receive tokens via nostr
- Optional caching using Redis ([NUT-19](https://github.com/cashubtc/nuts/blob/main/19.md))
- Optional authentication using Keycloak ([NUT-21](https://github.com/cashubtc/nuts/blob/main/21.md))

## The Cashu protocol
Different Cashu clients and mints use the same protocol to achieve interoperability. See the [documentation page](https://docs.cashu.space/) for more information on other projects. If you are interested in developing on your own Cashu project, please refer to the protocol specs [protocol specs](https://github.com/cashubtc/nuts).

## Easy Install: Nutshell wallet

The easiest way to use Cashu is to install the package it via pip:
```bash
pip install cashu
```

To update Cashu, use `pip install cashu -U`.

If you have problems running the command above on Ubuntu, run `sudo apt install -y pip pkg-config` and `pip install wheel`. On macOS, you might have to run `pip install wheel` and `brew install pkg-config`.

You can skip the entire next section about Poetry and jump right to [Using Cashu](#using-cashu).

## Easy Install: Nutshell mint

The easiest way to get a mint running is through Docker.

You can build the image yourself by running the following command. Make sure to adjust the environment variables in `docker-compose.yaml`.

```bash
docker compose up mint
```

Alternatively, you can use the pre-built Docker images, see [Running a mint](#docker).

## Manual install: Poetry
These steps help you install Python via pyenv and Poetry. If you already have Poetry running on your computer, you can skip this step and jump right to [Install Cashu](#poetry-install-cashu).

#### Poetry: Prerequisites

```bash
# on ubuntu:
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev python3-dev libsqlite3-dev ncurses-dev libbz2-dev libreadline-dev lzma-dev liblzma-dev

# install python using pyenv
curl https://pyenv.run | bash

# !! follow the instructions of pyenv init to setup pyenv !!
pyenv init

# restart your shell (or source your .rc file), then install python:
pyenv install 3.10.4

# install poetry
curl -sSL https://install.python-poetry.org | python3 - --version 1.8.5
echo export PATH=\"$HOME/.local/bin:$PATH\" >> ~/.bashrc
source ~/.bashrc
```
#### Poetry: Install Cashu Nutshell
```bash
# install nutshell
git clone https://github.com/cashubtc/nutshell.git nutshell
cd nutshell
git checkout <latest_tag>
pyenv local 3.10.4
poetry install
```

#### Poetry: Update Cashu
To update Cashu to the newest version enter
```bash
git pull && poetry install
```
#### Poetry: Using the Nutshell wallet

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
*Warning: this instance is just for demonstration purposes and development only. The satoshis are not real.*

Change the appropriate `.env` file settings to
```bash
MINT_URL=https://testnut.cashu.space
```

# Using Cashu
```bash
cashu info
```
This command shows information about your wallet.

#### Check balance
```bash
cashu balance
```

#### Generate a Lightning invoice

This command will return a Lightning invoice that you need to pay to mint new ecash tokens.

```bash
cashu invoice 420
```

The client will check every few seconds if the invoice has been paid. If you abort this step but still pay the invoice, you can use the command `cashu invoice <amount> --id <id>`.

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
cashuAeyJwcm9vZnMiOiBbey...
```

#### Receive tokens
To receive tokens, another user enters:
```bash
cashu receive cashuAeyJwcm9vZnMiOiBbey...
```

# Starting the wallet API daemon
Nutshell wallet can be used in daemon mode that can be controlled through a REST API:
```bash
cashu -d
```

You can find the API docs at [http://localhost:4448/docs](http://localhost:4448/docs).

# Running a mint
This command runs the mint on your local computer. Skip this step if you want to use the [public test mint](#test-instance) instead.

## Docker

```
docker run -d -p 3338:3338 --name nutshell -e MINT_BACKEND_BOLT11_SAT=FakeWallet -e MINT_LISTEN_HOST=0.0.0.0 -e MINT_LISTEN_PORT=3338 -e MINT_PRIVATE_KEY=TEST_PRIVATE_KEY cashubtc/nutshell:0.16.5 poetry run mint
```

## From this repository
Before you can run your own mint, make sure to enable a Lightning backend in `MINT_BACKEND_BOLT11_SAT` and set `MINT_PRIVATE_KEY` in your `.env` file.
```bash
poetry run mint
```

For testing, you can use Nutshell without a Lightning backend by setting `MINT_BACKEND_BOLT11_SAT=FakeWallet` in the `.env` file.

### NUT-19 Caching with Redis
To cache HTTP responses, you can either install Redis manually or use the docker compose file in `docker/docker-compose.yaml` to start Redis in a container.

Edit the `.env` file and uncomment the Redis lines:
```
MINT_REDIS_CACHE_ENABLED=TRUE
MINT_REDIS_CACHE_URL=redis://localhost:6379
```

# Running tests
To run the tests in this repository, first install the dev dependencies with
```bash
poetry install --with dev
```

Then, make sure to set up your mint's `.env` file to use a fake Lightning backend and disable Tor:
```bash
MINT_BACKEND_BOLT11_SAT=FakeWallet
TOR=FALSE
```
You can run the tests with
```bash
poetry run pytest tests
```


# Contributing

Developers are invited to contribute to Nutshell. Please see the [contribution guide](CONTRIBUTING.md).
