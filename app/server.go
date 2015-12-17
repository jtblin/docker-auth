package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/jtblin/docker-auth/auth/authenticator"
	_ "github.com/jtblin/docker-auth/auth/authenticator/backends"

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
	AuthorizerBackend       string
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
	}
}

// AddFlags adds flags for a specific DockerAuthServer to the specified FlagSet
func (s *DockerAuthServer) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&s.AppPort, "app-port", s.AppPort, "Http port")
	fs.StringVar(&s.Audience, "audience", s.Audience, "audience")
	fs.StringVar(&s.AuthenticatorBackend, "authn-backend", s.AuthenticatorBackend, "authn-backend")
	fs.StringVar(&s.AuthenticatorConfigFile, "authn-config-file", s.AuthenticatorConfigFile, "authn-config-file")
	fs.StringVar(&s.AuthorizerBackend, "authz-provider", s.AuthorizerBackend, "authz-provider")
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
	log.Infof("Successfully initialized authenticator backend: %q from the config file: %q\n", s.AuthenticatorBackend, s.AuthenticatorConfigFile)
	s.Authenticator = authnBackend
	r := mux.NewRouter()
	r.Handle("/token", appHandler(s.tokenHandler))
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

type TokenResponse struct {
	Token string `json:"token"`
}

func (s *DockerAuthServer) tokenHandler(w http.ResponseWriter, r *http.Request) *appError {
	username, password, ok := r.BasicAuth()
	if !ok {
		err := errors.New("Missing Authorization header")
		return &appError{err, err.Error(), http.StatusUnauthorized}
	}
	ok, _, err := s.Authenticator.Authenticate(username, password)
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
	scopes := []Scope{}
	for _, scope := range reqScopes {
		scopes = append(scopes, parseScope(scope))
	}
	// TODO: authz
	if len(scopes) > 0 {

	} else {
		// Authentication-only request ("docker login"), pass through.
	}
	token, err := s.GenerateToken(scopes, username)
	if err != nil {
		return &appError{err, err.Error(), http.StatusInternalServerError}
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	if err := json.NewEncoder(w).Encode(TokenResponse{token}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	return nil
}

// GenerateToken generates the json web token
func (s *DockerAuthServer) GenerateToken(scopes []Scope, username string) (string, error) {
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

// Scope represents the authorization scope
type Scope struct {
	Type    string   `json:"type"`
	Name    string   `json:"name"`
	Actions []string `json:"actions"`
}

// parseScope splits a scope item into a type, name and action pair that matches the spec
// Example: repository:samalba/my-app:pull,push
func parseScope(scope string) Scope {
	items := strings.Split(scope, ":")
	if len(items) != 3 {
		log.WithFields(log.Fields{"item": scope}).Error("Error parsing scope")
		return Scope{}
	}
	return Scope{
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
	log.Infof("Not found " + path)
	return nil
}

func write(w http.ResponseWriter, s string) {
	if _, err := w.Write([]byte(s)); err != nil {
		log.Errorf("Error writing response: %+v", err)
	}
}
