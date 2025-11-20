#!/bin/bash
set -e

# Create directories
mkdir -p certs/rootCA certs/intermediateCA certs/server certs/client certs/tmp certs/extras

echo "=== Generating Root CA ==="
openssl genrsa -out certs/rootCA/rootCA.key 4096
openssl req -x509 -new -nodes -key certs/rootCA/rootCA.key -sha256 -days 3650 \
  -out certs/rootCA/rootCA.crt -subj "/C=US/ST=CA/O=MyRootCA/CN=RootCA"

echo "=== Generating Intermediate CA ==="
openssl genrsa -out certs/intermediateCA/intermediate.key 4096
openssl req -new -key certs/intermediateCA/intermediate.key \
  -out certs/intermediateCA/intermediate.csr -subj "/C=US/ST=CA/O=MyIntermediateCA/CN=IntermediateCA"

cat > certs/intermediateCA/intermediate.ext <<EOF
basicConstraints=CA:TRUE,pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in certs/intermediateCA/intermediate.csr -CA certs/rootCA/rootCA.crt \
  -CAkey certs/rootCA/rootCA.key -CAcreateserial -out certs/intermediateCA/intermediate.crt \
  -days 1825 -sha256 -extfile certs/intermediateCA/intermediate.ext

echo "=== Generating Server Certificate ==="
openssl genrsa -out certs/server/server.key 2048
openssl req -new -key certs/server/server.key -out certs/server/server.csr \
  -subj "/C=US/ST=CA/O=MyServer/CN=localhost"

cat > certs/server/server.ext <<EOF
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in certs/server/server.csr -CA certs/intermediateCA/intermediate.crt \
  -CAkey certs/intermediateCA/intermediate.key -CAcreateserial -out certs/server/server.crt \
  -days 825 -sha256 -extfile certs/server/server.ext

echo "=== Generating Client Certificate ==="
openssl genrsa -out certs/client/client.key 2048
openssl req -new -key certs/client/client.key -out certs/client/client.csr \
  -subj "/C=US/ST=CA/O=MyClient/CN=Client"

cat > certs/client/client.ext <<EOF
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in certs/client/client.csr -CA certs/intermediateCA/intermediate.crt \
  -CAkey certs/intermediateCA/intermediate.key -CAcreateserial -out certs/client/client.crt \
  -days 825 -sha256 -extfile certs/client/client.ext

echo "=== Generating Extra Signed Certificate (Optional PKI Use) ==="
# Extra certificate signed by your Intermediate CA
openssl genrsa -out certs/extras/extra.key 2048
openssl req -new -key certs/extras/extra.key -out certs/extras/extra.csr \
  -subj "/C=US/ST=CA/O=ExtraCert/CN=ExtraCertificate"

cat > certs/extras/extra.ext <<EOF
basicConstraints=CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = DNS:extra.local,IP:127.0.0.1
EOF

openssl x509 -req -in certs/extras/extra.csr -CA certs/intermediateCA/intermediate.crt \
  -CAkey certs/intermediateCA/intermediate.key -CAcreateserial -out certs/extras/extra.crt \
  -days 825 -sha256 -extfile certs/extras/extra.ext

  rm -r ./certs/tmp
echo "=== Done! Full PKI Certificates Generated ==="
echo "Root CA: certs/rootCA/rootCA.crt"
echo "Intermediate CA: certs/intermediateCA/intermediate.crt"
echo "Server: certs/server/server.crt / key"
echo "Client: certs/client/client.crt / key"
echo "Extra signed cert: certs/extras/extra.crt / key"
