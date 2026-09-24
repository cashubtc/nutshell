VERSION := $(shell poetry version -s)

ruff:
	poetry run ruff check . --fix

ruff-check:
	poetry run ruff check .

fuzz:
	poetry run pytest tests/fuzz

mypy:
	poetry run mypy cashu --check-untyped-defs

format: ruff

check: ruff-check mypy

clean:
	rm -r cashu.egg-info/ || true
	find . -name ".DS_Store" -exec rm -f {} \; || true
	rm -rf dist || true
	rm -rf build || true
	rm -rf docker-build || true

package:
	poetry export -f requirements.txt --without-hashes --output requirements.txt
	poetry build --clean

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

.PHONY: resolve-compatibility-targets test-wallet-compatibility
resolve-compatibility-targets:
	poetry run python -m tests.compatibility --current-version "$(VERSION)"

test-wallet-compatibility: resolve-compatibility-targets
	CASHU_TEST_COMPATIBILITY=true \
	poetry run pytest tests/wallet/test_wallet_mint_compatibility.py -v

.PHONY: test-spark-regtest test-spark-backend-regtest test-spark-mint test-spark-wallet
test-spark-regtest:
	$(MAKE) test-spark-backend-regtest
	$(MAKE) test-spark-mint
	$(MAKE) test-spark-wallet

test-spark-backend-regtest:
	CASHU_SPARK_REGTEST=true \
	MINT_BACKEND_BOLT11_SAT=FakeWallet \
	MINT_BACKEND_BOLT11_USD=FakeWallet \
	TOR=FALSE \
	poetry run pytest tests/lightning/test_spark_regtest.py -v

test-spark-mint:
	CASHU_SPARK_REGTEST=true \
	MINT_BACKEND_BOLT11_SAT=SparkL2Wallet \
	MINT_BACKEND_BOLT11_USD=FakeWallet \
	TOR=FALSE \
	$(MAKE) test-mint

test-spark-wallet:
	CASHU_SPARK_REGTEST=true \
	MINT_BACKEND_BOLT11_SAT=SparkL2Wallet \
	MINT_BACKEND_BOLT11_USD=FakeWallet \
	TOR=FALSE \
	$(MAKE) test-wallet

install: package
	python -m pip install --upgrade dist/*.whl

upload: package
	poetry publish

install-pre-commit-hook:
	@echo "Installing pre-commit hook to git"
	@echo "Uninstall the hook with poetry run pre-commit uninstall"
	poetry run pre-commit install

pre-commit:
	poetry run pre-commit run --all-files

.PHONY: docker-build
docker-build:
	rm -rf docker-build || true
	mkdir -p docker-build
	git clone . docker-build
	cd docker-build
	docker buildx build -f Dockerfile -t cashubtc/nutshell:$(VERSION) --platform linux/amd64 .

clear-postgres:
	psql cashu -c "DROP SCHEMA public CASCADE;" -c "CREATE SCHEMA public;" -c "GRANT ALL PRIVILEGES ON SCHEMA public TO cashu;"
