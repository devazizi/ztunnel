package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"ztunnel/utils/config"
	tlsUtils "ztunnel/utils/tls"

	"github.com/gorilla/websocket"
)

/*
           ┌────────────────────────┐
           │   Start Client/Server  │
           └───────────┬───────────┘
                       │
                       ▼
         ┌────────────────────────────┐
         │ Establish WebSocket Tunnel │
         └───────────┬──────────────┘
                     │
                     ▼
          ┌─────────────────────────┐
          │ Tunnel Connected?       │
          ├───────────┬────────────┤
          │ Yes       │ No         │
          ▼           ▼
 ┌────────────────┐  ┌─────────────────────┐
 │ Start Reading  │  │ Wait & Retry Connect│
 │ & Writing Data │  └─────────────────────┘
 └───────┬────────┘
         │
         ▼
 ┌────────────────────────────┐
 │ Read from Local Client     │
 ├───────────┬────────────────┤
 │ EOF/Error │ Normal Data    │
 ▼           ▼
Close Local  Send over Tunnel (plaintext)
Connection   │
             ▼
   ┌─────────────────────┐
   │ Tunnel Read Message  │
   ├───────────┬─────────┤
   │ Error     │ Success │
   ▼           ▼
Reconnect    Write to Local Connection
Tunnel
*/

func main() {
	configFilePath := flag.String("config", "ztunnel-client-config.yaml", "ztunnel client config file")
	flag.Parse()

	if *configFilePath == "" {
		flag.Usage()
		return
	}

	var clientCfg config.ClientConfig
	if err := config.LoadYAMLConfig(*configFilePath, &clientCfg); err != nil {
		log.Fatal(err)
	}

	tlsConfig, err := tlsUtils.LoadClientTLSConfig(clientCfg.TLS)
	if err != nil {
		log.Fatal(err)
	}

	dialer := websocket.Dialer{TLSClientConfig: tlsConfig}

	// Dial loop: keep trying until connected
	var wsConn *websocket.Conn
	for {
		conn, _, err := dialer.Dial(fmt.Sprintf("wss://%v/ws", clientCfg.ServerConf.ServerAddress), nil)
		if err != nil {
			log.Println("WebSocket dial failed, retrying in 2s...", err)
			time.Sleep(2 * time.Second)
			continue
		}
		wsConn = conn
		log.Println("Connected to server")
		break
	}
	if wsConn == nil {
		log.Fatal("failed to establish websocket connection")
	}
	defer wsConn.Close()

	// Example: listen on local port from first port-forward entry
	if len(clientCfg.ServerConf.PortForwards) == 0 {
		log.Fatal("no port forwards configured")
	}

	listenAddr := clientCfg.ServerConf.PortForwards[0].Listen
	remote := clientCfg.ServerConf.PortForwards[0].Remote

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}
	defer listener.Close()
	log.Printf("Client listening on %v, forwarding to %v", listenAddr, remote)

	// 1) SEND AUTH ONLY ONCE
	authPayload := []byte(fmt.Sprintf("%s:::%s\n", clientCfg.ServerConf.Username, clientCfg.ServerConf.Password))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, authPayload); err != nil {
		log.Println("send credentials failed:", err)
		return
	}

	for {
		localConn, err := listener.Accept()
		if err != nil {
			log.Println("Accept error:", err)
			continue
		}

		go func(c net.Conn, remoteAddr string, ws *websocket.Conn) {
			defer c.Close()

			// 2) SEND REMOTE ADDRESS ONLY ONCE
			remoteHeader := []byte(remoteAddr + "\n")
			if err := ws.WriteMessage(websocket.BinaryMessage, remoteHeader); err != nil {
				log.Println("send remote address failed:", err)
				return
			}

			buf := make([]byte, 4096)

			for {
				n, err := c.Read(buf)
				if err != nil {
					if err != io.EOF {
						log.Println("local read error:", err)
					}
					return
				}

				// 3) TUNNEL ONLY PAYLOAD (NO AUTH, NO REMOTE ADDR)
				payload := buf[:n]

				if err := ws.WriteMessage(websocket.BinaryMessage, payload); err != nil {
					log.Println("write to server failed:", err)
					return
				}

				// 4) WAIT FOR SERVER RESPONSE
				_, msg, err := ws.ReadMessage()
				if err != nil {
					log.Println("server read error:", err)
					return
				}

				// 5) SEND BACK TO LOCAL
				_, err = c.Write(msg)
				if err != nil {
					log.Println("local write error:", err)
					return
				}
			}
		}(localConn, remote, wsConn)
	}
}
