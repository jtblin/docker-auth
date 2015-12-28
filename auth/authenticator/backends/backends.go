package backends

import (
	_ "github.com/jtblin/docker-auth/auth/authenticator/backends/dummy" // imports backends for Authenticator interface to avoid cycle error
	_ "github.com/jtblin/docker-auth/auth/authenticator/backends/ldap"  // imports backends for Authenticator interface to avoid cycle error
)
