package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"ztunnel/utils/config"
	tlsconfig "ztunnel/utils/tls_helper"

	"github.com/hashicorp/yamux"
)

func handleLocalConnection(localConn net.Conn, session *yamux.Session, username, password, remote string) {
	defer localConn.Close()

	stream, err := session.Open()
	if err != nil {
		log.Println("yamux open stream error:", err)
		return
	}
	defer stream.Close()

	// Send credentials and remote address
	fmt.Fprintf(stream, "%s:::%s\n", username, password)
	fmt.Fprintf(stream, "%s\n", remote)

	// Relay traffic
	done := make(chan struct{})
	go func() {
		io.Copy(stream, localConn)
		stream.Close()
		close(done)
	}()
	io.Copy(localConn, stream)
	<-done
}

func main() {
	configFilePath := flag.String("config", "ztunnel-client-config.yaml", "client config file")
	flag.Parse()

	var clientCfg config.ClientConfig
	if err := config.LoadYAMLConfig(*configFilePath, &clientCfg); err != nil {
		log.Fatal(err)
	}

	tlsConfig, err := tlsconfig.LoadClientTLSConfig(clientCfg.TLS)
	if err != nil {
		log.Fatal(err)
	}

	tlsConn, err := tls.Dial("tcp", clientCfg.ServerConf.ServerAddress, tlsConfig)
	if err != nil {
		log.Fatal("TLS dial failed:", err)
	}
	defer tlsConn.Close()

	// Start yamux session
	session, err := yamux.Client(tlsConn, nil)
	if err != nil {
		log.Fatal("yamux client error:", err)
	}
	defer session.Close()

	for _, pf := range clientCfg.ServerConf.PortForwards {
		listen, remote := pf.Listen, pf.Remote
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			log.Fatalf("failed to listen on %s: %v", listen, err)
		}
		log.Printf("Forwarding local %s -> remote %s", listen, remote)

		go func(l net.Listener, remoteAddr string) {
			for {
				localConn, err := l.Accept()
				if err != nil {
					log.Println("local accept error:", err)
					continue
				}
				go handleLocalConnection(localConn, session, clientCfg.ServerConf.Username, clientCfg.ServerConf.Password, remoteAddr)
			}
		}(listener, remote)
	}

	select {} // keep client running
}
