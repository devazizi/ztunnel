package ldapconn

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config holds LDAP connection settings
type Config struct {
	URL      string
	BaseDN   string
	AdminDN  string
	AdminPwd string
	UseTLS   bool
}

// LDAPClient wraps the connection
type LDAPClient struct {
	cfg  Config
	conn *ldap.Conn
}

// NewLDAPClient creates a new client but does not connect yet
func NewLDAPClient(cfg Config) *LDAPClient {
	return &LDAPClient{cfg: cfg}
}

// Connect establishes connection to LDAP server
func (c *LDAPClient) Connect() error {
	var conn *ldap.Conn
	var err error

	if c.cfg.UseTLS {
		conn, err = ldap.DialURL(c.cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	} else {
		conn, err = ldap.DialURL(c.cfg.URL)
	}
	if err != nil {
		return fmt.Errorf("failed to connect LDAP: %v", err)
	}

	// Set timeout
	conn.SetTimeout(5 * time.Second)

	c.conn = conn
	return nil
}

// Close connection
func (c *LDAPClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Authenticate checks user credentials against LDAP
func (c *LDAPClient) Authenticate(username, password string) (bool, error) {
	if c.conn == nil {
		if err := c.Connect(); err != nil {
			return false, err
		}
		defer c.Close()
	}

	// Step 1: Bind as admin to search user
	if err := c.conn.Bind(c.cfg.AdminDN, c.cfg.AdminPwd); err != nil {
		return false, fmt.Errorf("admin bind failed: %v", err)
	}

	// Step 2: Search for user DN
	searchRequest := ldap.NewSearchRequest(
		c.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(uid=%s)", ldap.EscapeFilter(username)),
		[]string{"dn"},
		nil,
	)

	res, err := c.conn.Search(searchRequest)
	if err != nil || len(res.Entries) == 0 {
		return false, fmt.Errorf("user not found")
	}

	userDN := res.Entries[0].DN

	// Step 3: Bind with user DN + password
	if err := c.conn.Bind(userDN, password); err != nil {
		return false, fmt.Errorf("invalid credentials")
	}

	return true, nil
}
