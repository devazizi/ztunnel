package main

import (
	"crypto/cipher"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"ztunnel/utils/jsonlogger"

	"ztunnel/utils"
	tlsUtils "ztunnel/utils/tls"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/chacha20poly1305"
)

type Client struct {
	Conn   *websocket.Conn
	Aead   cipher.AEAD
	SeqIn  uint64
	SeqOut uint64
}

var (
	log          = jsonlogger.EnableLogger()
	clients      = make(map[string]*Client)
	clientsMutex sync.Mutex
	upgrader     = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

// handleClient handles all messages from a client
func handleClient(c *Client) {
	for {
		_, msg, err := c.Conn.ReadMessage()
		if err != nil {
			log.Println("Read error:", err)
			break
		}

		if len(msg) < utils.NonceSize {
			log.Println("Message too short")
			continue
		}

		nonce := msg[:utils.NonceSize]
		ct := msg[utils.NonceSize:]

		pt, err := utils.Decrypt(c.Aead, c.SeqIn, nonce, ct)
		if err != nil {
			log.Println("Decrypt failed:", err)
			continue
		}
		c.SeqIn++

		// First bytes: destination "host:port\n", rest: payload
		idx := -1
		for i := 0; i < len(pt); i++ {
			if pt[i] == '\n' {
				idx = i
				break
			}
		}
		if idx == -1 {
			log.Println("Invalid packet format")
			continue
		}

		dest := string(pt[:idx])
		data := pt[idx+1:]

		go forwardToRemote(dest, data, c)
	}
}

// forwardToRemote forwards payload to the specified remote host and sends back the response
func forwardToRemote(dest string, payload []byte, c *Client) {
	conn, err := net.Dial("tcp", dest)
	if err != nil {
		log.Println("Remote connection failed:", err)
		return
	}
	defer conn.Close()

	_, err = conn.Write(payload)
	if err != nil {
		log.Println("Write to remote failed:", err)
		return
	}

	resp := make([]byte, 4096)
	for {
		n, err := conn.Read(resp)
		if err != nil {
			if err != io.EOF {
				log.Println("Read from remote failed:", err)
			}
			break
		}

		nonce, ct, err := utils.Encrypt(c.Aead, c.SeqOut, resp[:n])
		if err != nil {
			log.Println("Encrypt failed:", err)
			break
		}
		c.SeqOut++

		err = c.Conn.WriteMessage(websocket.BinaryMessage, append(nonce, ct...))
		if err != nil {
			log.Println("Write to client failed:", err)
			break
		}
	}
}

func main() {
	listen := flag.String("listen", "", "local port to listen on")
	tlsCertificatePath := flag.String("tls-certificate-conf", "", "path to TLS certificate")
	sharedKey := flag.String("shared-key", "", "shared key")
	flag.Parse()

	if *tlsCertificatePath == "" || *listen == "" || *sharedKey == "" {
		log.Error("Error: --listen, --tls-certificate-conf, --shard-key are required")
		return
	}

	tlsConfig, err := tlsUtils.LoadServerTLSConfig(*tlsCertificatePath, true)
	if err != nil {
		panic(err)
	}
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade failed:", err)
			return
		}

		if len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			log.Println("Client TLS CN: ", clientCert.Subject.CommonName)
			//log.Println("Client Cert:", clientCert.Subject.CommonName, "SANs:", clientCert.DNSNames,
			//	clientCert.IPAddresses, "Issuer:", clientCert.Issuer, "Valid:", clientCert.NotBefore, "to", clientCert.NotAfter)
		} else {
			fmt.Println("No client certificate provided")
		}

		key := []byte(*sharedKey)
		if len(key) != chacha20poly1305.KeySize {
			log.Fatal("Key must be 32 bytes")
		}

		aead, err := chacha20poly1305.New(key)
		if err != nil {
			log.Println("ChaCha20 setup failed:", err)
			conn.Close()
			return
		}

		client := &Client{Conn: conn, Aead: aead}

		clientsMutex.Lock()
		clients[r.RemoteAddr] = client
		clientsMutex.Unlock()

		log.Println("New client connected:", r.RemoteAddr)
		go handleClient(client)
	})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Println("Server listening on :8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
