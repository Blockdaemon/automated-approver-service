package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func testPrivateKeyB64(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

func validServerConfig(t *testing.T) ServerConfig {
	t.Helper()
	return ServerConfig{
		SecretManager: SecretsManagerLocal,
		PrivateKey:    testPrivateKeyB64(t),
		CWPBaseURL:    "https://vault.example.com/api/cwp",
		APIKey:        "cwp_test",
	}
}

func TestNewServer_RequiresCWPBaseURL(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.CWPBaseURL = ""

	_, err := newServer(cfg)
	require.ErrorContains(t, err, "cwp_base_url is required")
}

func TestNewServer_RequiresAPIKey(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.APIKey = ""

	_, err := newServer(cfg)
	require.ErrorContains(t, err, "api_key is required")
}

func TestNewServer_RejectsInvalidPollInterval(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.PollInterval = "not-a-duration"

	_, err := newServer(cfg)
	require.ErrorContains(t, err, "invalid poll_interval")
}

func TestNewServer_EnvOverridesConfig(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.CWPBaseURL = ""
	cfg.APIKey = ""
	cfg.PrivateKey = ""

	envKey := testPrivateKeyB64(t)
	t.Setenv("CWP_BASE_URL", "https://env.example.com/api/cwp")
	t.Setenv("CWP_API_KEY", "cwp_from_env")
	t.Setenv("CWP_PRIVATE_KEY", envKey)

	srv, err := newServer(cfg)
	require.NoError(t, err)
	require.Equal(t, "https://env.example.com/api/cwp", srv.cfg.CWPBaseURL)
	require.Equal(t, "cwp_from_env", srv.cfg.APIKey)
}

func TestHTTPPublicKeyAndHealth(t *testing.T) {
	srv, err := newServer(validServerConfig(t))
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	srv.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/public-key", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var pub GetPublicKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pub))
	require.NotEmpty(t, pub.PublicKey)

	rec = httptest.NewRecorder()
	srv.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	require.Equal(t, http.StatusOK, rec.Code)
}
