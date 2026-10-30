VERSION := $(shell poetry version -s)

ruff:
	poetry run ruff check . --fix

ruff-check:
	poetry run ruff check .

ruff-format:
	poetry run ruff format .

ruff-format-check:
	poetry run ruff format --check .

fuzz:
	poetry run pytest tests/fuzz

mypy:
	poetry run mypy cashu --check-untyped-defs

format: ruff ruff-format

check: ruff-check ruff-format-check mypy

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

.PHONY: compatibility-targets test-wallet-compatibility
compatibility-targets:
	poetry run python -m tests.compatibility

test-wallet-compatibility:
	@test -n "$$CASHU_TEST_MINT_IMAGE" || \
		(echo "Set CASHU_TEST_MINT_IMAGE, e.g. CASHU_TEST_MINT_IMAGE=cashubtc/nutshell:0.20.3" && exit 1)
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	poetry run pytest tests/wallet --cov-report xml --cov cashu

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
	@echo "Installing the pre-commit and commit-msg hooks to git"
	@echo "(the commit-msg hook enforces Conventional Commits, see AGENTS.md)"
	@echo "Uninstall with: poetry run pre-commit uninstall --hook-type pre-commit --hook-type commit-msg"
	poetry run pre-commit install --hook-type pre-commit --hook-type commit-msg

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
