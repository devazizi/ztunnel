# New key
openssl genrsa -out root.key 2048
# self-sign .key file
openssl req -new -key root.key -out root.pem -x509 -subj "/CN=ZTunnelRootCa" -days 3650
