from os import path

import setuptools

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

entry_points = {"console_scripts": ["cashu = cashu.wallet.cli:cli"]}

setuptools.setup(
    name="cashu",
    version="0.3.0",
    description="Ecash wallet and mint with Bitcoin Lightning support",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/callebtc/cashu",
    author="Calle",
    author_email="calle@protonmail.com",
    license="MIT",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    include_package_data=True,
    entry_points=entry_points,
)
