package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"ztunnel/utils"
	tlsUtils "ztunnel/utils/tls"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
)

func main() {

	listen := flag.String("listen", "", "local port to listen on")
	remote := flag.String("remote", "", "remote host:port to forward to")
	tlsCertificatePath := flag.String("tls-certificate-conf", "", "path to TLS certificate")
	sharedKey := flag.String("shared-key", "", "path to shared key")
	flag.Parse()

	if *remote == "" || *tlsCertificatePath == "" || *listen == "" || *sharedKey == "" {
		fmt.Println("Error: --remote, --listen, --tls-certificate-conf, --sharedKey are required")
		return
	}

	fmt.Println("Listening on port:", *listen)
	fmt.Println("Forwarding to remote:", *remote)

	tlsConfig, err := tlsUtils.LoadClientTLSConfig(*tlsCertificatePath)

	if err != nil {
		panic(err)
	}

	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}
	conn, _, err := dialer.Dial("wss://127.0.0.1:8443/ws", nil)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	key := []byte(*sharedKey)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	seqOut := uint64(0)
	seqIn := uint64(0)

	// Example: listen on local port 8080
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	log.Println("Client listening on 127.0.0.1:8080")

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go func(c net.Conn, remote string) {
			defer c.Close()
			buf := make([]byte, 4096)

			for {
				n, err := c.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Println("Read error:", err)
					}
					break
				}

				payload := append([]byte(remote+"\n"), buf[:n]...)
				nonce, ct, err := utils.Encrypt(aead, seqOut, payload)
				if err != nil {
					log.Println("Encrypt failed:", err)
					break
				}
				seqOut++

				err = conn.WriteMessage(websocket.BinaryMessage, append(nonce, ct...))
				if err != nil {
					log.Println("Write to server failed:", err)
					break
				}

				// Read server response
				_, msg, err := conn.ReadMessage()
				if err != nil {
					log.Println("Server read error:", err)
					break
				}
				if len(msg) < utils.NonceSize {
					log.Println("Response too short")
					break
				}

				respNonce := msg[:utils.NonceSize]
				respCT := msg[utils.NonceSize:]
				pt, err := utils.Decrypt(aead, seqIn, respNonce, respCT)
				if err != nil {
					log.Println("Decrypt failed:", err)
					break
				}
				seqIn++

				_, err = c.Write(pt)
				if err != nil {
					log.Println("Write to local connection failed:", err)
					break
				}
			}
		}(localConn, *remote)
	}
}
