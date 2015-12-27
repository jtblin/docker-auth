package dummy

import (
	"io"

	"github.com/jtblin/docker-auth/types"

	"github.com/jtblin/docker-auth/auth/authorizer"
)

const BackendName = "dummy"

// DummyBackend is an implementation of Authorizer Interface for dummies.
type DummyBackend struct {
}

func init() {
	authorizer.RegisterBackend(BackendName, func(config io.Reader) (authorizer.Interface, error) {
		return newDummyBackend(config)
	})
}

func newDummyBackend(config io.Reader) (authorizer.Interface, error) {
	return new(DummyBackend), nil
}

func (l *DummyBackend) Authorize(user types.User, scopes []types.Scope) ([]types.Scope, error) {
	return scopes, nil
}
