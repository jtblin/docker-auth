package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/jtblin/docker-auth/auth/authenticator"
	_ "github.com/jtblin/docker-auth/auth/authenticator/backends" // init authn backends
	"github.com/jtblin/docker-auth/auth/authorizer"
	_ "github.com/jtblin/docker-auth/auth/authorizer/backends" // init authz backends
	"github.com/jtblin/docker-auth/types"

	log "github.com/Sirupsen/logrus"
	"github.com/dgrijalva/jwt-go"
	"github.com/docker/libtrust"
	"github.com/gorilla/mux"
	"github.com/spf13/pflag"
)

// DockerAuthServer encapsulates all of the parameters necessary for starting up
// the web hooks server. These can either be set via command line or directly.
type DockerAuthServer struct {
	AppPort                 string
	Audience                string
	Authenticator           authenticator.Interface
	AuthenticatorBackend    string
	AuthenticatorConfigFile string
	Authorizer              authorizer.Interface
	AuthorizerBackend       string
	AuthorizerConfigFile    string
	Issuer                  string
	PublicKey               []byte
	PublicKeyFile           string
	SigningKey              []byte
	SigningKeyFile          string
	Verbose                 bool
}

// NewDockerAuthServer will create a new DockerAuthServer with default values.
func NewDockerAuthServer() *DockerAuthServer {
	return &DockerAuthServer{
		AppPort:              "5001",
		AuthenticatorBackend: "dummy",
		AuthorizerBackend:    "dummy",
	}
}

// AddFlags adds flags for a specific DockerAuthServer to the specified FlagSet
func (s *DockerAuthServer) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.AppPort, "app-port", s.AppPort, "Http port")
	fs.StringVar(&s.Audience, "audience", s.Audience, "audience")
	fs.StringVar(&s.AuthenticatorBackend, "authn-backend", s.AuthenticatorBackend, "authn-backend")
	fs.StringVar(&s.AuthenticatorConfigFile, "authn-config-file", s.AuthenticatorConfigFile, "authn-config-file")
	fs.StringVar(&s.AuthorizerBackend, "authz-backend", s.AuthorizerBackend, "authz-backend")
	fs.StringVar(&s.AuthorizerConfigFile, "authz-config-file", s.AuthorizerConfigFile, "authz-config-file")
	fs.StringVar(&s.Issuer, "issuer", s.Issuer, "issuer")
	fs.StringVar(&s.PublicKeyFile, "public-key-file", s.PublicKeyFile, "Public key file path")
	fs.StringVar(&s.SigningKeyFile, "signing-key-file", s.SigningKeyFile, "Signing key path")
	fs.BoolVar(&s.Verbose, "verbose", false, "Verbose")
}

// Run runs the specified DockerAuthServer.
func (s *DockerAuthServer) Run() error {
	if s.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	publicKey, err := ioutil.ReadFile(s.PublicKeyFile)
	if err != nil {
		return err
	}
	s.PublicKey = publicKey
	signingKey, err := ioutil.ReadFile(s.SigningKeyFile)
	if err != nil {
		return err
	}
	s.SigningKey = signingKey
	authnBackend, err := authenticator.InitAuthenticatorBackend(s.AuthenticatorBackend, s.AuthenticatorConfigFile)
	if err != nil {
		return err
	}
	log.Infof("Successfully initialized authentication backend: %q from the config file: %q", s.AuthenticatorBackend, s.AuthenticatorConfigFile)
	s.Authenticator = authnBackend
	authzBackend, err := authorizer.InitAuthorizerBackend(s.AuthorizerBackend, s.AuthorizerConfigFile)
	if err != nil {
		return err
	}
	log.Infof("Successfully initialized authorization backend: %q from the config file: %q", s.AuthorizerBackend, s.AuthorizerConfigFile)
	s.Authorizer = authzBackend
	r := mux.NewRouter()
	r.Handle("/v2/token", appHandler(s.tokenHandler))
	r.Handle("/{path:.*}", appHandler(s.notFoundHandler))
	log.Infof("Listening on port %s", s.AppPort)
	return http.ListenAndServe(":"+s.AppPort, r)
}

type appError struct {
	Error   error  `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

type appHandler func(http.ResponseWriter, *http.Request) *appError

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e := fn(w, r); e != nil { // e is *appError, not os.Error.
		fmt.Println("error:", e)
		log.WithFields(log.Fields{
			"code": e.Code,
		}).Error(e.Message)
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.WriteHeader(e.Code)
		if err := json.NewEncoder(w).Encode(e); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type tokenResponse struct {
	Token string `json:"token"`
}

func (s *DockerAuthServer) tokenHandler(w http.ResponseWriter, r *http.Request) *appError {
	log.Debugf("Token handler. Headers: %+v", r.Header)
	username, password, ok := r.BasicAuth()
	if !ok {
		err := errors.New("Missing Authorization header")
		return &appError{err, err.Error(), http.StatusUnauthorized}
	}
	ok, user, err := s.Authenticator.Authenticate(username, password)
	if err != nil || !ok {
		if err != nil {
			return &appError{err, err.Error(), http.StatusInternalServerError}
		}
		if !ok {
			err := errors.New("Authentication failed")
			return &appError{err, err.Error(), http.StatusUnauthorized}
		}
	}
	reqScopes := r.URL.Query()["scope"]
	log.Debugf("Request scopes: %+v", reqScopes)
	scopes := []types.Scope{}
	for _, scope := range reqScopes {
		scopes = append(scopes, parseScope(scope))
	}
	// Authentication-only requests e.g. "docker login" pass through.
	if len(scopes) > 0 {
		if scopes, err = s.Authorizer.Authorize(user, scopes); err != nil {
			return &appError{err, err.Error(), http.StatusInternalServerError}
		}
	}
	token, err := s.GenerateToken(scopes, username)
	if err != nil {
		return &appError{err, err.Error(), http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(tokenResponse{token}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return nil
}

// GenerateToken generates the json web token
func (s *DockerAuthServer) GenerateToken(scopes []types.Scope, username string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["access"] = scopes
	token.Claims["aud"] = s.Audience
	token.Claims["iss"] = s.Issuer
	token.Claims["exp"] = time.Now().Add(time.Hour * 1).Unix()
	token.Claims["sub"] = username
	publicKey, err := libtrust.UnmarshalPublicKeyPEM([]byte(s.PublicKey))
	if err != nil {
		return "", err
	}
	token.Header["jwk"] = publicKey
	token.Header["typ"] = "JWT"
	// Sign and get the complete encoded token as a string
	log.Debugf("Token: %+v", token)
	return token.SignedString(s.SigningKey)
}

// parseScope splits a scope item into a type, name and action pair that matches the spec
// Example: repository:samalba/my-app:pull,push
func parseScope(scope string) types.Scope {
	items := strings.Split(scope, ":")
	if len(items) != 3 {
		log.WithFields(log.Fields{"item": scope}).Error("Error parsing scope")
		return types.Scope{}
	}
	return types.Scope{
		Type:    items[0],
		Name:    items[1],
		Actions: strings.Split(items[2], ","),
	}
}

func (s *DockerAuthServer) notFoundHandler(w http.ResponseWriter, r *http.Request) *appError {
	vars := mux.Vars(r)
	path := vars["path"]
	w.WriteHeader(404)
	write(w, "Not found "+path)
	log.Infof("Not found %s", path)
	return nil
}

func write(w io.Writer, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		log.Errorf("Error writing response to socket: %+v", err)
	}
}
