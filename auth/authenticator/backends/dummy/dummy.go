package dummy

import (
	"io"

	"github.com/jtblin/docker-auth/auth/authenticator"
	"github.com/jtblin/docker-auth/types"
)

const backendName = "dummy"

// Backend is an implementation of Authenticator Interface for dummies.
type Backend struct {
}

// User represents a dummy user state.
type User struct {
}

// From returns the backend name
func (u *User) From() string {
	return backendName
}

func init() {
	authenticator.RegisterBackend(backendName, func(config io.Reader) (authenticator.Interface, error) {
		return newDummyBackend(config)
	})
}

func newDummyBackend(config io.Reader) (authenticator.Interface, error) {
	return new(Backend), nil
}

// Authenticate always says OK
func (l *Backend) Authenticate(username, password string) (bool, types.User, error) {
	return true, &User{}, nil
}
