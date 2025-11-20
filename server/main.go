package main

import (
	"crypto/cipher"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"log"
	"net"
	"net/http"
	"sync"
	"ztunnel/utils"
	tlsUtils "ztunnel/utils/tls"
)

type Client struct {
	Conn   *websocket.Conn
	Aead   cipher.AEAD
	SeqIn  uint64
	SeqOut uint64
	ACL    map[string]bool // allowed local services
}

var (
	clients      = make(map[string]*Client)
	clientsMutex sync.Mutex
	portBase     = 9000
)

func authorize(clientID, service string) bool {
	clientsMutex.Lock()
	defer clientsMutex.Unlock()
	c, ok := clients[clientID]
	if !ok {
		return false
	}
	return c.ACL[service]
}

func handleClient(c *Client, clientID string) {
	for {
		_, msg, err := c.Conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}
		nonce := msg[:utils.NonceSize]
		ct := msg[utils.NonceSize:]
		pt, err := utils.Decrypt(c.Aead, c.SeqIn, nonce, ct)
		if err != nil {
			log.Println("Decrypt failed:", err)
			continue
		}
		c.SeqIn++

		// Parse destination port (simple protocol)
		dest := string(pt[:5]) // first 5 bytes = destination port string
		data := pt[5:]

		if !authorize(clientID, dest) {
			log.Println("Unauthorized access attempt by", clientID, "to port", dest)
			continue
		}

		go forwardToLocal(dest, data, c)
	}
}

func forwardToLocal(dest string, payload []byte, c *Client) {
	conn, err := net.Dial("tcp", "127.0.0.1:"+dest)
	if err != nil {
		log.Println("Local connection failed:", err)
		return
	}
	defer conn.Close()
	conn.Write(payload)

	resp := make([]byte, 4096)
	n, _ := conn.Read(resp)
	nonce, ct, _ := utils.Encrypt(c.Aead, c.SeqOut, resp[:n])
	c.SeqOut++
	c.Conn.WriteMessage(websocket.BinaryMessage, append(nonce, ct...))
}

func main() {
	tlsConfig, err := tlsUtils.LoadTLSConfig("/home/ali/Documents/development/self-projects/ztunnel/server-cert.yaml", true)
	if err != nil {
		panic(err.Error())
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, _ := upgrader.Upgrade(w, r, nil)

		// Derive AEAD key (ephemeral exchange could be added here)
		key := make([]byte, chacha20poly1305.KeySize)
		aead, _ := chacha20poly1305.New(key)

		clientID := r.Header.Get("Client-ID")
		c := &Client{Conn: conn, Aead: aead, ACL: map[string]bool{"8080": true}}
		clientsMutex.Lock()
		clients[clientID] = c
		clientsMutex.Unlock()

		go handleClient(c, clientID)
	})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler:   nil,
	}
	log.Println("Tunnel server listening on :8443")
	_ = server.ListenAndServeTLS("", "") // empty strings because TLS is handled via TLSConfig
	if err != nil {
		log.Fatal(err)
	}
}
