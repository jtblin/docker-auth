package authenticator

import (
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/jtblin/docker-auth/types"

	log "github.com/Sirupsen/logrus"
)

// All registered auth backends.
var backendsMutex sync.Mutex
var backends = make(map[string]Factory)

// Factory is a function that returns an authenticator.Interface.
// The config parameter provides an io.Reader handler to the factory in
// order to load specific configurations. If no configuration is provided
// the parameter is nil.
type Factory func(config io.Reader) (Interface, error)

// Interface represents an authenticator
type Interface interface {
	// Authenticate authenticates the user against the backend server
	Authenticate(username, password string) (bool, types.User, error)
}

// RegisterBackend registers an authentication backend
func RegisterBackend(name string, backend Factory) {
	backendsMutex.Lock()
	defer backendsMutex.Unlock()
	if _, found := backends[name]; found {
		log.Fatalf("Authenticator backend %q was registered twice", name)
	}
	log.Infof("Registered authenticator backend %q", name)
	backends[name] = backend
}

// GetAuthenticatorBackend creates an instance of the named authenticator backend, or nil if
// the name is not known.  The error return is only used if the named provider
// was known but failed to initialize. The config parameter specifies the
// io.Reader handler of the configuration file for the authenticator backend, or nil
// for no configuation.
func GetAuthenticatorBackend(name string, config io.Reader) (Interface, error) {
	backendsMutex.Lock()
	defer backendsMutex.Unlock()
	f, found := backends[name]
	if !found {
		return nil, nil
	}
	return f(config)
}

// InitAuthenticatorBackend creates an instance of the named authenticator backend.
func InitAuthenticatorBackend(name string, configFilePath string) (Interface, error) {
	var cloud Interface
	var err error

	if name == "" {
		log.Info("No authenticator backend specified.")
		return nil, nil
	}

	if configFilePath != "" {
		var config *os.File
		config, err = os.Open(configFilePath)
		if err != nil {
			log.Fatalf("Couldn't open authenticator backend configuration %s: %#v",
				configFilePath, err)
		}

		defer func() {
			if err := config.Close(); err != nil {
				log.Errorf("Error closing config file: %v", err)
			}
		}()
		cloud, err = GetAuthenticatorBackend(name, config)
	} else {
		// Pass explicit nil so plugins can actually check for nil. See
		// "Why is my nil error value not equal to nil?" in golang.org/doc/faq.
		cloud, err = GetAuthenticatorBackend(name, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("could not init authenticator backend %q: %v", name, err)
	}
	if cloud == nil {
		return nil, fmt.Errorf("unknown authenticator backend %q", name)
	}

	return cloud, nil
}
