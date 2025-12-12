package config

import tlsconfig "ztunnel/utils/tls"

type ServerConfig struct {
	ServerConfig ServerGeneralConfig `yaml:"serverConfig"`
	TLS          tlsconfig.TLSConfig `yaml:"tls"`
}

type ServerGeneralConfig struct {
	Listen            string     `yaml:"listen"`
	LDAPServerAddress string     `yaml:"ldapServerAddress"`
	LDAPBaseDN        string     `yaml:"ldapBaseDN"`
	LDAPAdminDN       string     `yaml:"ldapAdminDN"`
	LDAPAdminPassword string     `yaml:"ldapAdminPassword"`
	RBAC              RBACConfig `yaml:"rbac"`
}

type RBACConfig struct {
	Enabled       bool                   `yaml:"enabled"`
	Groups        map[string]AccessRules `yaml:"groups"`
	Organizations map[string]AccessRules `yaml:"organizations"`
}

type AccessRules struct {
	Allow []string `yaml:"allow"`
}
