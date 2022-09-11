# cashu

## Install

```bash
git clone https://github.com/callebtc/cashu.git
sudo apt install -y build-essential pkg-config libffi-dev libpq-dev zlib1g-dev libssl-dev
# on mac: brew install postgres

# install python using pyenv
curl https://pyenv.run | bash
echo export PYENV_ROOT="$HOME/.pyenv" >> .bashrc
echo command -v pyenv >/dev/null || export PATH="$PYENV_ROOT/bin:$PATH" >> .bashrc
echo eval "$(pyenv init -)" >> .bashrc
echo eval "$(pyenv virtualenv-init -)" >> .bashrc
source .bashrc
pyenv install 3.9.13

# install poetry
curl -sSL https://install.python-poetry.org | python3 -

# install cashu
cd cashu
pyenv local 3.9.13
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