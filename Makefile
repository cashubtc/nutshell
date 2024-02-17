ruff:
	poetry run ruff check . --fix

ruff-check:
	poetry run ruff check .

mypy:
	poetry run mypy cashu --check-untyped-defs

format: ruff

check: ruff-check mypy

clean:
	rm -r cashu.egg-info/ || true
	find . -name ".DS_Store" -exec rm -f {} \; || true
	rm -rf dist || true
	rm -rf build || true

package:
	poetry export -f requirements.txt --without-hashes --output requirements.txt
	make clean
	python setup.py sdist bdist_wheel

test:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	poetry run pytest tests --cov-report xml --cov cashu

test-lndrest:
	PYTHONUNBUFFERED=1 \
	DEBUG=true \
	MINT_LIGHTNING_BACKEND=LndRestWallet \
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

docker-build:
	rm -rf docker-build || true
	mkdir -p docker-build
	git clone . docker-build
	cd docker-build
	docker buildx build -f Dockerfile -t cashubtc/nutshell:0.15.0 --platform linux/amd64 .
	# docker push cashubtc/nutshell:0.15.0
