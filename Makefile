UV := uv --project .
VERSION := $(shell $(UV) version --short)

ruff:
	$(UV) run ruff check . --fix

ruff-check:
	$(UV) run ruff check .

fuzz:
	$(UV) run pytest tests/fuzz

mypy:
	$(UV) run mypy cashu --check-untyped-defs

format: ruff

check: ruff-check mypy

clean:
	rm -r cashu.egg-info/ || true
	find . -name ".DS_Store" -exec rm -f {} \; || true
	rm -rf dist || true
	rm -rf build || true
	rm -rf docker-build || true

package:
	$(UV) export --format requirements.txt --no-dev --no-hashes --no-emit-project --output-file requirements.txt
	make clean
	$(UV) build

test:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	$(UV) run pytest tests --cov-report xml --cov cashu

test-wallet:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	$(UV) run pytest tests/wallet --cov-report xml --cov cashu

test-mint:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	$(UV) run pytest tests/mint --cov-report xml --cov cashu

test-lndrest:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	MINT_BACKEND_BOLT11_SAT=LndRestWallet \
	MINT_LND_REST_ENDPOINT=https://localhost:8081/ \
	MINT_LND_REST_CERT=../cashu-regtest-enviroment/data/lnd-3/tls.cert \
	MINT_LND_REST_MACAROON=../cashu-regtest-enviroment/data/lnd-3/data/chain/bitcoin/regtest/admin.macaroon \
	$(UV) run pytest tests/test_cli.py --cov-report xml --cov cashu

install:
	make clean
	$(UV) build
	$(UV) pip install --upgrade dist/*

upload:
	make clean
	$(UV) build
	$(UV) publish

install-pre-commit-hook:
	@echo "Installing pre-commit hook to git"
	@echo "Uninstall the hook with uv run pre-commit uninstall"
	$(UV) run pre-commit install

pre-commit:
	$(UV) run pre-commit run --all-files

.PHONY: docker-build
docker-build:
	rm -rf docker-build || true
	mkdir -p docker-build
	git clone . docker-build
	cd docker-build
	docker buildx build -f Dockerfile -t cashubtc/nutshell:$(VERSION) --platform linux/amd64 .

clear-postgres:
	psql cashu -c "DROP SCHEMA public CASCADE;" -c "CREATE SCHEMA public;" -c "GRANT ALL PRIVILEGES ON SCHEMA public TO cashu;"
