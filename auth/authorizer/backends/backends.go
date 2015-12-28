package backends

import (
	_ "github.com/jtblin/docker-auth/auth/authorizer/backends/dummy" // imports backends for Authorizer interface to avoid cycle error
)
