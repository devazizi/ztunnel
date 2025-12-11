### How to run client
```bash
go run client/main.go --listen localhost:8000 --remote google.com:443 --tls-certificate-conf ./client-cert.yaml --shared-key 12345678901234567890123456789012
```

### How to run server
```shell
go run ./server/main.go  --listen 0.0.0.0:8443  --tls-certificate-conf ./server-cert.yaml --shared-key 12345678901234567890123456789012
```

### Generate radom key shared key to secure connection
```shell
openssl rand -hex 16
```

### Caution: persist certs directory
