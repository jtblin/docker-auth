package dummy

import (
	"io"

	"github.com/jtblin/docker-auth/auth/authenticator"
	"github.com/jtblin/docker-auth/types"
)

const BackendName = "dummy"

// DummyBackend is an implementation of Authenticator Interface for dummies.
type DummyBackend struct {
}

// User represents a dummy user state.
type User struct {
}

// From returns the backend name
func (u *User) From() string {
	return BackendName
}

func init() {
	authenticator.RegisterBackend(BackendName, func(config io.Reader) (authenticator.Interface, error) {
		return newDummyBackend(config)
	})
}

func newDummyBackend(config io.Reader) (authenticator.Interface, error) {
	return new(DummyBackend), nil
}

func (l *DummyBackend) Authenticate(username, password string) (bool, types.User, error) {
	return true, &User{}, nil
}
