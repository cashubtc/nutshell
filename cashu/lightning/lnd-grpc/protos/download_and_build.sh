#!/bin/bash

# Launch this script from `cashu/lightning/lnd-grpc/protos`
pip install grpcio grpcio-tools googleapis-common-protos mypy-protobuf types-protobuf
git clone https://github.com/googleapis/googleapis.gits
curl -o lightning.proto -s https://raw.githubusercontent.com/lightningnetwork/lnd/master/lnrpc/lightning.proto
python -m grpc_tools.protoc --proto_path=googleapis:. --mypy_out=. --python_out=. --grpc_python_out=. lightning.proto