package main

import (
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"net"
	"ztunnel/utils"
	tls "ztunnel/utils/tls"
)

func main() {
	tlsConfig, err := tls.LoadTLSConfig("/home/ali/Documents/development/self-projects/ztunnel/client-cert.yaml", true)
	if err != nil {
		panic(err.Error())
	}
	tlsConfig.InsecureSkipVerify = true
	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}
	conn, _, err := dialer.Dial("wss://localhost:8443/ws", nil)
	if err != nil {
		panic(err.Error())
	}

	key := make([]byte, chacha20poly1305.KeySize)
	aead, _ := chacha20poly1305.New(key)
	seqOut := uint64(0)

	localConn, _ := net.Dial("tcp", "google.com:8080")
	for {
		buf := make([]byte, 4096)
		n, _ := localConn.Read(buf)
		nonce, ct, _ := utils.Encrypt(aead, seqOut, append([]byte("8080"), buf[:n]...))
		seqOut++
		conn.WriteMessage(websocket.BinaryMessage, append(nonce, ct...))

		// Read response from server
		_, msg, _ := conn.ReadMessage()
		respNonce := msg[:utils.NonceSize]
		respCT := msg[utils.NonceSize:]
		pt, _ := utils.Decrypt(aead, seqOut, respNonce, respCT)
		localConn.Write(pt)
	}
}
