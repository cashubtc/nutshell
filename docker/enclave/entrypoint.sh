#!/bin/bash
set -e

# Generate secure random hex for the mint private key if not provided
if [ -z "$MINT_PRIVATE_KEY" ]; then
    echo "Generating new MINT_PRIVATE_KEY..."
    export MINT_PRIVATE_KEY=$(openssl rand -hex 32)
fi

# Generate a 24 word mnemonic for the Spark L2 wallet if not provided
if [ -z "$MINT_SPARK_MNEMONIC" ]; then
    echo "Generating new MINT_SPARK_MNEMONIC..."
    export MINT_SPARK_MNEMONIC=$(python3 -c "from mnemonic import Mnemonic; m = Mnemonic('english'); print(m.generate(strength=256))")
fi

echo "=========================================================="
echo "Enclave Mint Started"
echo "Data Directory: ${CASHU_DIR:-/app/data}"
echo "Database: ${MINT_DATABASE:-sqlite}"
echo "=========================================================="

# Start the mint
exec poetry run mint
