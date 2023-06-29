isort:
	poetry run isort --profile black . --skip cashu/nostr

black:
	poetry run black . --exclude cashu/nostr

flake8:
	poetry run flake8

format:
	make isort
	make black
	make mypy
	make flake8

mypy:
	poetry run mypy cashu --ignore-missing

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
	pytest tests/

install:
	make clean
	python setup.py sdist bdist_wheel
	pip install --upgrade dist/*

upload:
	make clean
	python setup.py sdist bdist_wheel
	twine upload --repository pypi dist/*
