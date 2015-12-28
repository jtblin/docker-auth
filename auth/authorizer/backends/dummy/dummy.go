package dummy

import (
	"io"

	"github.com/jtblin/docker-auth/types"

	"github.com/jtblin/docker-auth/auth/authorizer"
)

const backendName = "dummy"

// Backend is an implementation of Authorizer Interface for dummies.
type Backend struct {
}

func init() {
	authorizer.RegisterBackend(backendName, func(config io.Reader) (authorizer.Interface, error) {
		return newDummyBackend(config)
	})
}

func newDummyBackend(config io.Reader) (authorizer.Interface, error) {
	return new(Backend), nil
}

// Authorize authorizes a dummy user to do anything
func (l *Backend) Authorize(user types.User, scopes []types.Scope) ([]types.Scope, error) {
	return scopes, nil
}
