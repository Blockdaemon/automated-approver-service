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
	"os"
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

func TestNewServer_ConfirmerOnlyFailsWithoutIV(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.ConfirmerOnly = true
	// No IV server running, so lookup will fail.
	cfg.CWPBaseURL = "http://127.0.0.1:1/api/cwp"

	_, err := newServer(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "confirmer_only requires IV GET /api/users/info")
}

func TestNewServer_ConfirmerOnlyEnvOverride(t *testing.T) {
	// Stand up a fake IV for env-triggered confirmer_only.
	iv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Name":"Bot","Email":"envbot@example.com","Status":"Active","Role":"Admin"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(iv.Close)

	cfg := validServerConfig(t)
	cfg.CWPBaseURL = iv.URL + "/api/cwp"
	t.Setenv("CWP_CONFIRMER_ONLY", "true")

	srv, err := newServer(cfg)
	require.NoError(t, err)
	require.True(t, srv.confirmerOnly)
	require.Equal(t, "envbot@example.com", srv.selfUserID)
}

func TestNewServer_ConfirmerOnlyResolvesFromIV(t *testing.T) {
	// Stand up a fake IV that returns an email from GET /api/users/info.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/users/info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Name":"Bot","Email":"resolved@example.com","Status":"Active","Role":"Admin"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	cfg := validServerConfig(t)
	cfg.ConfirmerOnly = true
	cfg.CWPBaseURL = srv.URL + "/api/cwp"

	s, err := newServer(cfg)
	require.NoError(t, err)
	require.Equal(t, "resolved@example.com", s.selfUserID)
}

func TestLoadConfig_AppliesDefaults(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	require.NoError(t, os.WriteFile(path, []byte("cwp_base_url: https://vault.example.com/api/cwp\n"), 0o600))

	cfg, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, 9294, cfg.Port)
	require.Equal(t, SecretsManagerLocal, cfg.SecretManager)
	require.Equal(t, "10s", cfg.PollInterval)
	require.Equal(t, "debug", cfg.LogLevel)
	require.False(t, cfg.ConfirmerOnly)
}

func TestNewServer_KeyVaultRequiresURL(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.SecretManager = SecretsManagerAzure
	t.Setenv("AZURE_KEY_VAULT_URI", "")

	_, err := newServer(cfg)
	require.ErrorContains(t, err, "key_vault_url or AZURE_KEY_VAULT_URI is required")
}

func TestLoadConfig_AcceptsKeyVault(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	body := "secret_manager: keyvault\nkey_vault_url: https://example.vault.azure.net/\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, SecretsManagerAzure, cfg.SecretManager)
	require.Equal(t, "https://example.vault.azure.net/", cfg.KeyVaultURL)
}

func TestLoadConfig_RejectsBadLogLevel(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	require.NoError(t, os.WriteFile(path, []byte("log_level: verbose\n"), 0o600))

	_, err := loadConfig(path)
	require.ErrorContains(t, err, "log_level")
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
