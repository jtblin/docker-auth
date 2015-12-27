package types

// User represents the state of an authenticated user
type User interface {
	// From returns from which backend the user was retrieved
	From() string
}

// Scope represents the authorization scope
type Scope struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}
