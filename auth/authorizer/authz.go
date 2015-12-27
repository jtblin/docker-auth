package authorizer

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

// Factory is a function that returns an authorizer.Interface.
// The config parameter provides an io.Reader handler to the factory in
// order to load specific configurations. If no configuration is provided
// the parameter is nil.
type Factory func(config io.Reader) (Interface, error)

type Interface interface {
	// Authorize authorizes the user for the given scopes against the backend server
	Authorize(user types.User, scopes []types.Scope) ([]types.Scope, error)
}

func RegisterBackend(name string, backend Factory) {
	backendsMutex.Lock()
	defer backendsMutex.Unlock()
	if _, found := backends[name]; found {
		log.Fatalf("Authorizer backend %q was registered twice", name)
	}
	log.Infof("Registered authorizer backend %q", name)
	backends[name] = backend
}

// GetAuthorizerBackend creates an instance of the named authorizer backend, or nil if
// the name is not known.  The error return is only used if the named provider
// was known but failed to initialize. The config parameter specifies the
// io.Reader handler of the configuration file for the authorizer backend, or nil
// for no configuation.
func GetAuthorizerBackend(name string, config io.Reader) (Interface, error) {
	backendsMutex.Lock()
	defer backendsMutex.Unlock()
	f, found := backends[name]
	if !found {
		return nil, nil
	}
	return f(config)
}

// InitAuthorizerBackend creates an instance of the named authorizer backend.
func InitAuthorizerBackend(name string, configFilePath string) (Interface, error) {
	var cloud Interface
	var err error

	if name == "" {
		log.Info("No authorizer backend specified.")
		return nil, nil
	}

	if configFilePath != "" {
		var config *os.File
		config, err = os.Open(configFilePath)
		if err != nil {
			log.Fatalf("Couldn't open authorizer backend configuration %s: %#v",
				configFilePath, err)
		}

		defer config.Close()
		cloud, err = GetAuthorizerBackend(name, config)
	} else {
		// Pass explicit nil so plugins can actually check for nil. See
		// "Why is my nil error value not equal to nil?" in golang.org/doc/faq.
		cloud, err = GetAuthorizerBackend(name, nil)
	}

	if err != nil {
		return nil, fmt.Errorf("could not init authorizer backend %q: %v", name, err)
	}
	if cloud == nil {
		return nil, fmt.Errorf("unknown authorizer backend %q", name)
	}

	return cloud, nil
}
