#!/bin/bash

# *** RUN THIS FROM THE ROOT OF THE PROJECT ***

BASE_DIR=./cashu/mint/management_rpc/protos

echo "Ensuring grpcio is installed..."
poetry add grpcio grpcio-tools

echo "Compiling proto files..."
poetry run python3 -m grpc_tools.protoc -I$BASE_DIR --python_out=$BASE_DIR --grpc_python_out=$BASE_DIR $BASE_DIR/management.proto

echo "Finished!"