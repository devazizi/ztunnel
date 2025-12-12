package ldapauth

import (
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
)

// ===========================
// Singleton Config
// ===========================

type LdapConfig struct {
	ServerAddress   string // e.g., "ldap://127.0.0.1:389"
	BaseDN          string // e.g., "dc=ztunnel,dc=local"
	AdminDN         string // e.g., "cn=admin,dc=ztunnel,dc=local"
	AdminPassword   string
	UserSearchField string // usually "uid" or "cn"
}

func LdapAuthenticate(ldapConfig LdapConfig, username, password string) bool {
	Cfg := ldapConfig

	// 1) CONNECT
	conn, err := ldap.DialURL(Cfg.ServerAddress)
	if err != nil {
		log.Println("LDAP connect error:", err)
		return false
	}
	defer conn.Close()

	// 2) BIND AS ADMIN
	err = conn.Bind(Cfg.AdminDN, Cfg.AdminPassword)
	if err != nil {
		log.Println("LDAP admin bind error:", err)
		return false
	}

	// 3) SEARCH FOR USER DN
	searchReq := ldap.NewSearchRequest(
		Cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(%s=%s)", Cfg.UserSearchField, username),
		[]string{"dn"},
		nil,
	)

	res, err := conn.Search(searchReq)
	if err != nil {
		return false
	}

	if len(res.Entries) == 0 {
		return false
	}

	userDN := res.Entries[0].DN

	// 4) BIND AS USER TO VERIFY PASSWORD
	err = conn.Bind(userDN, password)
	if err != nil {
		return false
	}

	return true
}
