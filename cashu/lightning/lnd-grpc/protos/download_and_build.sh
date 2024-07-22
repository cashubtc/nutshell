#!/bin/bash

# Launch this script from `cashu/lightning/lnd-grpc/protos`

GOOGLEAPIS_DIR="googleapis"

# Check if the googleapis directory exists
if [ -d "$GOOGLEAPIS_DIR" ]; then
  echo "$GOOGLEAPIS_DIR directory already exists. Skipping clone."
else
  echo "Cloning googleapis..."
  echo "If this doesn't work, clone it manually."
  git clone https://github.com/googleapis/googleapis.git $GOOGLEAPIS_DIR
fi

echo "Installing pip packages..."
pip install grpcio grpcio-tools googleapis-common-protos mypy-protobuf types-protobuf

echo "curl-ing protos"
curl -o lightning.proto -s https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/lightning.proto
curl -o router.proto -s https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/routerrpc/router.proto

echo "auto-generate code from protos..."
python -m grpc_tools.protoc --proto_path=googleapis:. --mypy_out=. --python_out=. --grpc_python_out=. lightning.proto
python -m grpc_tools.protoc --proto_path=googleapis:. --mypy_out=. --python_out=. --grpc_python_out=. router.proto

echo "Done!"