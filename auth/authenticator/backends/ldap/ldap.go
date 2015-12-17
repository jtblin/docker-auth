package ldap

import (
	"errors"
	"io"
	"io/ioutil"
	"strconv"

	log "github.com/Sirupsen/logrus"
	"github.com/gogits/gogs/modules/auth/ldap"
	"github.com/scalingdata/gcfg"

	"github.com/jtblin/docker-auth/auth/authenticator"
)

const BackendName = "ldap"

// LDAPBackend is an implementation of Authenticator Interface for LDAP.
type LDAPBackend struct {
	cfg    *LDAPConfig
	source *ldap.Source
}

// LDAPConfig contains the config for the ldap backend
type LDAPConfig struct {
	Global struct {
		Base   string
		Filter string
		Host   string
		Port   int
		TLS    bool
	}

	Attributes struct {
		Email string
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

	return &LDAPBackend{cfg: &cfg, source: &ldap.Source{
		UserBase:      cfg.Global.Base,
		Host:          cfg.Global.Host,
		Port:          cfg.Global.Port,
		UseSSL:        cfg.Global.TLS,
		BindDN:        cfg.Bind.DN,
		BindPassword:  string(password),
		Filter:        cfg.Global.Filter,
		AttributeMail: cfg.Attributes.Email,
	}}, nil

}

func (l *LDAPBackend) Authenticate(username, password string) (bool, error) {
	u, name, sn, email, admin, ok := l.source.SearchEntry(username, password, false)
	log.WithFields(log.Fields{
		"username":      u,
		"name":          name,
		"sn":            sn,
		"email":         email,
		"admin":         admin,
		"authenticated": strconv.FormatBool(ok),
	}).Info("LDAP authenticator")
	return ok, nil
}
