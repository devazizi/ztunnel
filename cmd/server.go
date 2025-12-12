package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"ztunnel/utils/config"
	"ztunnel/utils/jsonlogger"
	ldapauth "ztunnel/utils/ldap_conn"
	tlsconfig "ztunnel/utils/tls_helper"

	"github.com/hashicorp/yamux"
)

var logger = jsonlogger.EnableLogger()

func handleStream(stream net.Conn, ldapConfig ldapauth.LdapConfig) {
	defer stream.Close()
	reader := bufio.NewReader(stream)

	// Read credentials
	credLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Println("read credentials error:", err)
		return
	}
	parts := strings.SplitN(strings.TrimSpace(credLine), ":::", 2)
	if len(parts) != 2 {
		logger.Println("invalid credential format")
		return
	}
	username := strings.TrimSpace(parts[0])
	password := strings.TrimSpace(parts[1])

	// LDAP authentication
	if !ldapauth.LdapAuthenticate(ldapConfig, username, password) {
		logger.Println("LDAP auth failed for", username)
		return
	}

	// Read remote address
	remoteLine, err := reader.ReadString('\n')
	if err != nil {
		logger.Println("read remote address error:", err)
		return
	}
	remoteAddr := strings.TrimSpace(remoteLine)
	logger.Println("Connecting to remote:", remoteAddr)

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		logger.Println("remote dial failed:", err)
		return
	}
	defer remoteConn.Close()

	// Relay traffic
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, reader) // data from client stream to remote
	}()
	go func() {
		defer wg.Done()
		io.Copy(stream, remoteConn) // data from remote to client stream
	}()
	wg.Wait()
}

func main() {

	configFilePath := flag.String("config", "ztunnel-server-config.yaml", "server config file")
	flag.Parse()

	var serverCfg config.ServerConfig
	err := config.LoadYAMLConfig(*configFilePath, &serverCfg)
	if err != nil {
		log.Fatal(err)
	}

	tlsConfig, _ := tlsconfig.LoadServerTLSConfig(serverCfg.TLS)
	ldapConfig := ldapauth.LdapConfig{
		ServerAddress:   serverCfg.ServerConfig.LDAPServerAddress,
		AdminDN:         serverCfg.ServerConfig.LDAPAdminDN,
		AdminPassword:   serverCfg.ServerConfig.LDAPAdminPassword,
		BaseDN:          serverCfg.ServerConfig.LDAPBaseDN,
		UserSearchField: "cn",
	}

	listener, err := tls.Listen("tcp", serverCfg.ServerConfig.Listen, tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	logger.Println(fmt.Sprintf("Server listening on %s", serverCfg.ServerConfig.Listen))

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Println("accept error:", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			logger.Println("not a TLS connection")
			conn.Close()
			continue
		}

		err = tlsConn.Handshake()
		if err != nil {
			logger.Println("TLS handshake failed:", err)
			conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer c.Close()
			session, err := yamux.Server(c, nil)
			if err != nil {
				logger.Println("yamux server error:", err)
				return
			}
			for {
				stream, err := session.Accept()
				if err != nil {
					logger.Println("yamux accept error:", err)
					return
				}
				go handleStream(stream, ldapConfig)
			}
		}(tlsConn)
	}
}
