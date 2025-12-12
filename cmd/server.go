package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"ztunnel/utils/config"
	"ztunnel/utils/jsonlogger"
	ldapauth "ztunnel/utils/ldap_conn"
	tlsUtils "ztunnel/utils/tls"

	"github.com/gorilla/websocket"
)

type Client struct {
	Conn *websocket.Conn
}

var (
	log          = jsonlogger.EnableLogger()
	clients      = make(map[string]*Client)
	clientsMutex sync.Mutex
	upgrader     = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
)

func handleClient(ldapConfig ldapauth.LdapConfig, c *Client, clientCertificateCommonName string) {
	_, msg, err := c.Conn.ReadMessage()
	if err != nil {
		log.Println("auth read error:", err)
		c.Conn.Close()
		return
	}

	cred := string(msg)
	parts := strings.SplitN(cred, ":::", 2)
	if len(parts) != 2 {
		log.Println("invalid credential format")
		c.Conn.Close()
		return
	}
	username := strings.TrimSpace(parts[0])
	password := strings.TrimSpace(parts[1])

	if clientCertificateCommonName != username {
		log.Error("peering CN with username failed")
		c.Conn.Close()
		return
	}

	if !ldapauth.LdapAuthenticate(ldapConfig, username, password) {
		log.Println("LDAP auth failed")
		c.Conn.Close()
		return
	}
	log.Println("LDAP auth OK for", username)

	_, msg, err = c.Conn.ReadMessage()
	if err != nil {
		log.Println("remote header read error:", err)
		c.Conn.Close()
		return
	}

	remoteAddr := strings.TrimSpace(string(msg))
	log.Println("Connecting to remote:", remoteAddr)

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Println("remote dial failed:", err)
		c.Conn.Close()
		return
	}

	go relayWebsocketToTcp(c.Conn, remoteConn)
	relayTcpToWebsocket(remoteConn, c.Conn)
}

func relayWebsocketToTcp(ws *websocket.Conn, remote net.Conn) {
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			remote.Close()
			return
		}

		_, err = remote.Write(msg)
		if err != nil {
			ws.Close()
			return
		}
	}
}

func relayTcpToWebsocket(remote net.Conn, ws *websocket.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := remote.Read(buf)
		if err != nil {
			ws.Close()
			return
		}
		ws.WriteMessage(websocket.BinaryMessage, buf[:n])
	}
}

func main() {
	configFilePath := flag.String("config", "ztunnel-server-config.yaml", "ztunnel server config file")
	flag.Parse()

	if *configFilePath == "" {
		flag.Usage()
		return
	}

	var serverCfg config.ServerConfig
	err := config.LoadYAMLConfig(*configFilePath, &serverCfg)
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig, err := tlsUtils.LoadServerTLSConfig(serverCfg.TLS)
	if err != nil {
		panic(err)
	}

	ldapConfig := ldapauth.LdapConfig{
		ServerAddress:   serverCfg.ServerConfig.LDAPServerAddress,
		AdminDN:         serverCfg.ServerConfig.LDAPAdminDN,
		AdminPassword:   serverCfg.ServerConfig.LDAPAdminPassword,
		BaseDN:          serverCfg.ServerConfig.LDAPBaseDN,
		UserSearchField: "cn",
	}

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("Upgrade failed:", err)
			return
		}

		clientCert := r.TLS.PeerCertificates[0]
		if len(r.TLS.PeerCertificates) > 0 {

			log.Println("Client TLS CN:", clientCert.Subject.CommonName)
		} else {
			fmt.Println("No client certificate provided")
		}

		client := &Client{Conn: conn}

		clientsMutex.Lock()
		clients[r.RemoteAddr] = client
		clientsMutex.Unlock()

		log.Println(map[string]any{"IP": r.RemoteAddr})
		go handleClient(ldapConfig, client, clientCert.Subject.CommonName)
	})

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Println("Server listening on :8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
