VERSION := $(shell poetry version -s)

ruff:
	poetry run ruff check . --fix

# Staged files only for ruff + whitespace hooks (focused PRs). Whole-tree lint fix: `make ruff`.
# CI parity: `make pre-commit` (full tree, same hooks as CI). Optional one-shot lint+hooks: `make format-full`.
format:
	@py=$$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null | grep '\.py$$' || true); \
	[ -z "$$py" ] || poetry run ruff check --fix $$py
	@files=$$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true); \
	[ -z "$$files" ] || poetry run pre-commit run mixed-line-ending --files $$files
	@files=$$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true); \
	[ -z "$$files" ] || poetry run pre-commit run trailing-whitespace --files $$files
	@files=$$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true); \
	[ -z "$$files" ] || poetry run pre-commit run end-of-file-fixer --files $$files

# Optional: run Ruff lint --fix on the whole tree, then every pre-commit hook (no Ruff formatter).
format-full:
	poetry run ruff check . --fix
	poetry run pre-commit run --all-files

ruff-check:
	poetry run ruff check .

fuzz:
	poetry run pytest tests/fuzz

mypy:
	poetry run mypy cashu --check-untyped-defs

check: ruff-check mypy

clean:
	rm -r cashu.egg-info/ || true
	find . -name ".DS_Store" -exec rm -f {} \; || true
	rm -rf dist || true
	rm -rf build || true
	rm -rf docker-build || true

package:
	poetry export -f requirements.txt --without-hashes --output requirements.txt
	make clean
	python setup.py sdist bdist_wheel

test:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	poetry run pytest tests --cov-report xml --cov cashu

test-wallet:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	poetry run pytest tests/wallet --cov-report xml --cov cashu

test-mint:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	poetry run pytest tests/mint --cov-report xml --cov cashu

test-lndrest:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	MINT_BACKEND_BOLT11_SAT=LndRestWallet \
	MINT_LND_REST_ENDPOINT=https://localhost:8081/ \
	MINT_LND_REST_CERT=../cashu-regtest-enviroment/data/lnd-3/tls.cert \
	MINT_LND_REST_MACAROON=../cashu-regtest-enviroment/data/lnd-3/data/chain/bitcoin/regtest/admin.macaroon \
	poetry run pytest tests/test_cli.py --cov-report xml --cov cashu

install:
	make clean
	python setup.py sdist bdist_wheel
	pip install --upgrade dist/*

upload:
	make clean
	python setup.py sdist bdist_wheel
	twine upload --repository pypi dist/*

install-pre-commit-hook:
	@echo "Installing pre-commit hook to git"
	@echo "Uninstall the hook with poetry run pre-commit uninstall"
	poetry run pre-commit install

pre-commit:
	poetry run pre-commit run --all-files

.PHONY: docker-build format format-full ruff ruff-check pre-commit check
docker-build:
	rm -rf docker-build || true
	mkdir -p docker-build
	git clone . docker-build
	cd docker-build
	docker buildx build -f Dockerfile -t cashubtc/nutshell:$(VERSION) --platform linux/amd64 .

clear-postgres:
	psql cashu -c "DROP SCHEMA public CASCADE;" -c "CREATE SCHEMA public;" -c "GRANT ALL PRIVILEGES ON SCHEMA public TO cashu;"
