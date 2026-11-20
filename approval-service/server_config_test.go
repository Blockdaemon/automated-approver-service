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

func TestNewServer_ConfirmerOnlyFailsWithoutUsersMe(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.ConfirmerOnly = true
	cfg.CWPBaseURL = "http://127.0.0.1:1/api/cwp"

	_, err := newServer(cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "confirmer_only requires CWP GET /users/me")
}

func TestNewServer_ConfirmerOnlyEnvOverride(t *testing.T) {
	cwp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/me" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ID":"envbot@example.com","Name":"Bot","Active":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(cwp.Close)

	cfg := validServerConfig(t)
	cfg.CWPBaseURL = cwp.URL
	t.Setenv("CWP_CONFIRMER_ONLY", "true")

	srv, err := newServer(cfg)
	require.NoError(t, err)
	require.True(t, srv.confirmerOnly)
	require.Equal(t, "envbot@example.com", srv.selfUserID)
}

func TestNewServer_ConfirmerOnlyResolvesFromUsersMe(t *testing.T) {
	cwp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/users/me" {
			require.Equal(t, "Bearer cwp_test", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ID":"Resolved@example.com","Name":"Bot","Active":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(cwp.Close)

	cfg := validServerConfig(t)
	cfg.ConfirmerOnly = true
	cfg.CWPBaseURL = cwp.URL

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
	require.Equal(t, "debug", cfg.LogLevel)
	require.False(t, cfg.ConfirmerOnly)
	require.Equal(t, defaultAPIKeySecretName, cfg.APIKeySecretName)
	require.Equal(t, defaultPrivateKeySecretName, cfg.PrivateKeySecretName)
}

func TestLoadConfig_CustomSecretNames(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	body := "" +
		"secret_manager: keyvault\n" +
		"key_vault_url: https://example.vault.azure.net/\n" +
		"api_key_secret_name: approver-a-cwp-api-key\n" +
		"private_key_secret_name: approver-a-tls-private-key\n"
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	cfg, err := loadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "approver-a-cwp-api-key", cfg.APIKeySecretName)
	require.Equal(t, "approver-a-tls-private-key", cfg.PrivateKeySecretName)
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

	rec = httptest.NewRecorder()
	srv.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotEmpty(t, rec.Body.Bytes())
}
