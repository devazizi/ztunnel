package config

import tlsconfig "ztunnel/utils/tls_helper"

type ClientConfig struct {
	ServerConf ServerConf          `yaml:"serverConf"`
	TLS        tlsconfig.TLSConfig `yaml:"tls"`
}

type ServerConf struct {
	ServerAddress string        `yaml:"serverAddress"`
	Username      string        `yaml:"username"`
	Password      string        `yaml:"password"`
	PortForwards  []PortForward `yaml:"portForwards"`
}

type PortForward struct {
	Listen string `yaml:"listen"`
	Remote string `yaml:"remote"`
}
