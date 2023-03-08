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
	make clean
	python setup.py sdist bdist_wheel
	
check-yaml:
	cat codecov.yml | curl --data-binary @- https://codecov.io/validate	

test:
	pytest tests/
	
install:
	make clean
	python setup.py sdist bdist_wheel
	pip install --upgrade dist/* 
	
upload-test:
	make clean
	python setup.py sdist bdist_wheel
	twine upload --repository testpypi dist/*
	
upload:
	make clean
	python setup.py sdist bdist_wheel
	twine upload --repository pypi dist/*

pypi-install-test:
	mkdir ~/tmp/cashu
	cd ~/tmp/cashu
	rm -r ~/tmp/cashu/*
	conda remove --name cashu --all -y
	conda create -n cashu python=3.7 -y
	pip install -i https://test.pypi.org/simple/ cashu --extra-index-url https://pypi.org/simple
