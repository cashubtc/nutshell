isort:
	poetry run isort --profile black . --skip cashu/nostr

black:
	poetry run black . --exclude cashu/nostr

format:
	make isort
	make black
	make mypy

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

mint-backup:
	mkdir -p data/backup
	mkdir -p data/backup/mint
	cp data/mint/mint.sqlite3 data/backup/mint/mint.sqlite3

export-csv:
	make mint-backup
	mkdir -p data/export
	sqlite3 -cmd ".mode csv" -cmd ".headers on" -cmd ".output 'data/export/burns.csv'" data/mint/mint.sqlite3 "SELECT amount, C, id FROM proofs_used;"
	sqlite3 -cmd ".mode csv" -cmd ".headers on" -cmd ".output 'data/export/mints.csv'" data/mint/mint.sqlite3 "SELECT amount, B_b AS B_, C_b AS C_, id FROM promises;"
