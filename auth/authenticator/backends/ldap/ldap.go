package ldap

import (
	"errors"
	"io"
	"io/ioutil"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/jtblin/go-ldap-client"
	"github.com/scalingdata/gcfg"

	"github.com/jtblin/docker-auth/auth/authenticator"
)

const BackendName = "ldap"

// LDAPBackend is an implementation of Authenticator Interface for LDAP.
type LDAPBackend struct {
	cfg    *LDAPConfig
	client *ldap.LDAPClient
}

// LDAPConfig contains the config for the ldap backend
type LDAPConfig struct {
	Global struct {
		Base      string
		Filter    string
		Host      string
		Port      int
		TLS       bool
		Attribute []string
	}

	Filter struct {
		User   string
		Groups string
	}

	Bind struct {
		DN           string
		PasswordFile string
	}
}

func init() {
	authenticator.RegisterBackend(BackendName, func(config io.Reader) (authenticator.Interface, error) {
		return newLDAPBackend(config)
	})
}

func newLDAPBackend(config io.Reader) (authenticator.Interface, error) {
	var cfg LDAPConfig

	if config == nil {
		return nil, errors.New("missing required ldap config")
	}
	err := gcfg.ReadInto(&cfg, config)
	if err != nil {
		return nil, err
	}

	log.Debugf("LDAP config: %+v", cfg)
	password, err := ioutil.ReadFile(cfg.Bind.PasswordFile)
	if err != nil {
		return nil, err
	}

	return &LDAPBackend{cfg: &cfg, client: &ldap.LDAPClient{
		Base:         cfg.Global.Base,
		Host:         cfg.Global.Host,
		Port:         cfg.Global.Port,
		UseSSL:       cfg.Global.TLS,
		BindDN:       cfg.Bind.DN,
		BindPassword: strings.TrimSpace(string(password)),
		UserFilter:   cfg.Filter.User,
		GroupFilter:  cfg.Filter.Groups,
		Attributes:   cfg.Global.Attribute,
	}}, nil
}

type User struct {
	Attributes map[string]string
	Groups     []string
}

func (lb *LDAPBackend) Authenticate(username, password string) (bool, interface{}, error) {
	lc := lb.client
	defer lc.Close()
	ok, attributes, err := lc.Authenticate(username, password)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, nil, errors.New("Authentication failed")
	}
	user := &User{Attributes: attributes}
	groups, err := lc.GetGroupsOfUser(username)
	if err != nil {
		return true, user, err
	}
	user.Groups = groups
	log.Debugf("User groups: %+v", groups)
	return true, user, nil
}
