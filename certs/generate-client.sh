# New CSR (with private key)
openssl req -new -sha256 -nodes -subj '/CN=ZtunnelClient' -keyout client.key -out client.csr
# sign CSR with root CA
openssl x509 -req -in client.csr -CA root.pem -CAkey root.key -CAcreateserial -out client.pem -days 1000

# verify client
openssl verify -verbose -CAfile root.pem client.pem
