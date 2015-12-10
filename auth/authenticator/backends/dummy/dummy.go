package dummy

import (
	"io"

	"bitbucket.org/jtblin/docker-auth/auth/authenticator"
)

const BackendName = "dummy"

// DummyBackend is an implementation of Authenticator Interface for dummies.
type DummyBackend struct {
}

func init() {
	authenticator.RegisterBackend(BackendName, func(config io.Reader) (authenticator.Interface, error) {
		return newDummyBackend(config)
	})
}

func newDummyBackend(config io.Reader) (authenticator.Interface, error) {
	return new(DummyBackend), nil
}

func (l *DummyBackend) Authenticate(username, password string) (bool, error) {
	return true, nil
}
