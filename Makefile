VERSION := $(shell uv version --short)

ruff:
	uv run --locked ruff check . --fix

ruff-check:
	uv run --locked ruff check .

fuzz:
	uv run --locked pytest tests/fuzz

mypy:
	uv run --locked mypy cashu --check-untyped-defs

format: ruff

check: ruff-check mypy

clean:
	rm -r cashu.egg-info/ || true
	find . -name ".DS_Store" -exec rm -f {} \; || true
	rm -rf dist || true
	rm -rf build || true
	rm -rf docker-build || true

package:
	uv export --locked --no-dev --no-emit-project --no-hashes --output-file requirements.txt
	uv build --clear --no-sources

test:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	uv run --locked pytest tests --cov-report xml --cov cashu

test-wallet:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	uv run --locked pytest tests/wallet --cov-report xml --cov cashu

test-mint:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	uv run --locked pytest tests/mint --cov-report xml --cov cashu

.PHONY: compatibility-targets test-wallet-compatibility
compatibility-targets:
	uv run --locked python -m tests.compatibility

test-wallet-compatibility:
	@test -n "$$CASHU_TEST_MINT_IMAGE" || \
		(echo "Set CASHU_TEST_MINT_IMAGE, e.g. CASHU_TEST_MINT_IMAGE=cashubtc/nutshell:0.20.3" && exit 1)
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	uv run --locked pytest tests/wallet --cov-report xml --cov cashu

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
	uv run --locked pytest tests/lightning/test_spark_regtest.py -v

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
	uv sync --locked --no-dev --no-editable

upload: package
	uv publish

install-pre-commit-hook:
	@echo "Installing pre-commit hook to git"
	@echo "Uninstall the hook with uv run --locked pre-commit uninstall"
	uv run --locked pre-commit install

pre-commit:
	uv run --locked pre-commit run --all-files

.PHONY: docker-build
docker-build:
	rm -rf docker-build || true
	mkdir -p docker-build
	git clone . docker-build
	cd docker-build
	docker buildx build -f Dockerfile -t cashubtc/nutshell:$(VERSION) --platform linux/amd64 .

clear-postgres:
	psql cashu -c "DROP SCHEMA public CASCADE;" -c "CREATE SCHEMA public;" -c "GRANT ALL PRIVILEGES ON SCHEMA public TO cashu;"
