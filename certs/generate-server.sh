cat > san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ZTunnelServer

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost
EOF

echo "=== 3. Generate Server Key and CSR ==="
openssl req -new -sha256 -nodes -keyout server.key -out server.csr -config san.cnf

echo "=== 4. Sign Server Certificate with Root CA ==="
openssl x509 -req -in server.csr -CA root.pem -CAkey root.key -CAcreateserial \
  -out server.pem -days 1000 -extfile san.cnf -extensions v3_req

echo "=== 5. Verify Server Certificate ==="
openssl verify -verbose -CAfile root.pem server.pem
