#!/bin/bash

echo "*** WARNING: this script is only to be used for development/testing purposes! ***"
sleep 2
echo -n "Continue? [Y/n]: "
read -r response
if [[ "$response" =~ ^[Yy]$ ]]; then
    echo "Continuing..."
else
    exit 1
fi

echo "Generating CA certificate..."
openssl genpkey -algorithm RSA -out ca_private.pem
openssl req -x509 -new -key ca_private.pem -sha256 -days 365 -out ca_cert.pem -subj "/CN=cashuCA"

echo "Generating server certificate"
openssl genpkey -algorithm RSA -out server_private.pem
openssl req -new -key server_private.pem -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_private.pem -CAcreateserial -out server_cert.pem -days 365 -sha256

echo "Generating client certificate"
openssl genpkey -algorithm RSA -out client_private.pem
openssl req -new -key client_private.pem -out client.csr -subj "/CN=client"
openssl x509 -req -in client.csr -CA ca_cert.pem -CAkey ca_private.pem -CAcreateserial -out client_cert.pem -days 365 -sha256

echo "Removing intermediate fiels..."
rm server.csr client.csr ca_cert.srl

echo "All done!"
