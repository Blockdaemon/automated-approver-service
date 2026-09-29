package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
)

const operationTypeMakeTransaction = "make transaction"

// Server polls CWP for pending approvals and signs every listed intent.
// GET /public-key remains for registering the ECDSA P-256 key on the bot user.
//
// This is a reference implementation for testing. Extend checkMakeTransactionIntent
// with your own policy rules before any production use.
type Server struct {
	echo   *echo.Echo
	logger zerolog.Logger

	cfg ServerConfig

	privateKey    *ecdsa.PrivateKey
	cwp           approvalAPI
	pollInterval  time.Duration
	pollCancel    context.CancelFunc
	checkHook     func(MakeTransactionIntent, GenericIntent) error
	confirmerOnly bool
	selfUserID    string
}

func newServer(cfg ServerConfig) (*Server, error) {
	echoInstance := echo.New()
	echoInstance.HideBanner = true

	level := parseLogLevel(cfg.LogLevel)
	var lgr zerolog.Logger
	if level <= zerolog.DebugLevel {
		lgr = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger().Level(level)
	} else {
		lgr = zerolog.New(os.Stderr).
			With().Timestamp().Logger().Level(level)
	}

	if err := setup(echoInstance, lgr); err != nil {
		return nil, err
	}

	var err error
	var secretManager SecretsManagerAPI
	switch cfg.SecretManager {
	case SecretsManagerAWS:

		secretManager, err = NewSecretClientAWS(
			getRegion(),
			zerolog.New(os.Stdout).With().Timestamp().Caller().Logger(),
		)
		if err != nil {
			return nil, err
		}
	case SecretsManagerAzure:
		vaultURL := resolveKeyVaultURL(cfg.KeyVaultURL)
		if vaultURL == "" {
			return nil, fmt.Errorf("key_vault_url or AZURE_KEY_VAULT_URI is required")
		}
		secretManager, err = NewSecretClientAzure(
			vaultURL,
			zerolog.New(os.Stdout).With().Timestamp().Caller().Logger(),
		)
		if err != nil {
			return nil, err
		}
	case SecretsManagerLocal:
		secretManager = NewSecretClientLocal()
	default:
		return nil, fmt.Errorf("secret manager type %s is not supported", cfg.SecretManager)
	}

	if v := os.Getenv("CWP_API_KEY_SECRET_NAME"); v != "" {
		cfg.APIKeySecretName = v
	}
	if v := os.Getenv("CWP_PRIVATE_KEY_SECRET_NAME"); v != "" {
		cfg.PrivateKeySecretName = v
	}
	if strings.TrimSpace(cfg.APIKeySecretName) == "" {
		cfg.APIKeySecretName = defaultAPIKeySecretName
	}
	if strings.TrimSpace(cfg.PrivateKeySecretName) == "" {
		cfg.PrivateKeySecretName = defaultPrivateKeySecretName
	}

	if cfg.SecretManager != SecretsManagerLocal {
		cfg.PrivateKey, err = secretManager.GetSecret(cfg.PrivateKeySecretName)
		if err != nil {
			return nil, fmt.Errorf("failed to get signing private key %s: %s", cfg.PrivateKeySecretName, err)
		}

		cfg.APIKey, err = secretManager.GetSecret(cfg.APIKeySecretName)
		if err != nil {
			return nil, fmt.Errorf("failed to get cwp api key %s: %s", cfg.APIKeySecretName, err)
		}
	}

	if v := os.Getenv("CWP_BASE_URL"); v != "" {
		cfg.CWPBaseURL = v
	}
	if v := os.Getenv("CWP_API_KEY"); v != "" {
		cfg.APIKey = v
	}
	if v := os.Getenv("CWP_PRIVATE_KEY"); v != "" {
		cfg.PrivateKey = v
	}
	if v := os.Getenv("CWP_CONFIRMER_ONLY"); v != "" {
		cfg.ConfirmerOnly = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv("CWP_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}

	privateKeyDer, err := cfg.PrivateKeyDecoded()
	if err != nil {
		return nil, fmt.Errorf("failed to decode pk: %s", err)
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pk: %s", err)
	}

	lgr.Debug().
		Str("signature_verification_key", base64.StdEncoding.EncodeToString(getPublicKey(privateKey))).
		Msg("loaded signing key")

	if strings.TrimSpace(cfg.CWPBaseURL) == "" {
		return nil, fmt.Errorf("cwp_base_url is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("api_key is required (CWP_API_KEY, config api_key, or secret %s)", cfg.APIKeySecretName)
	}

	pollInterval := 10 * time.Second
	if cfg.PollInterval != "" {
		pollInterval, err = time.ParseDuration(cfg.PollInterval)
		if err != nil {
			return nil, fmt.Errorf("invalid poll_interval: %w", err)
		}
		if pollInterval <= 0 {
			return nil, fmt.Errorf("poll_interval must be greater than zero")
		}
	}

	cwpCli := newCWPClient(cfg.CWPBaseURL, cfg.APIKey)

	var selfUserID string
	if cfg.ConfirmerOnly {
		resolved, err := resolveUserFromIV(cfg.CWPBaseURL, cfg.APIKey)
		if err != nil {
			return nil, fmt.Errorf("confirmer_only requires IV GET /api/users/info: %w", err)
		}
		selfUserID = strings.ToLower(resolved)
		lgr.Info().
			Str("self_user_id", selfUserID).
			Msg("confirmer-only mode: will skip entries not initiated by self")
	}

	server := Server{
		cfg:           cfg,
		echo:          echoInstance,
		logger:        lgr,
		privateKey:    privateKey,
		cwp:           cwpCli,
		pollInterval:  pollInterval,
		confirmerOnly: cfg.ConfirmerOnly,
		selfUserID:    selfUserID,
	}

	echoInstance.GET("/public-key", server.GetPublicKey)
	echoInstance.GET("/health", server.Health)

	return &server, nil
}

type ServerConfig struct {
	Port int `yaml:"port"`

	// ASN.1 DER encoded private key
	PrivateKey string `yaml:"private_key"`

	SecretManager string `yaml:"secret_manager"`

	// KeyVaultURL is the Azure Key Vault URI used when secret_manager is
	// keyvault. AZURE_KEY_VAULT_URI overrides it.
	KeyVaultURL string `yaml:"key_vault_url"`

	// CWPBaseURL is the CWP approvals root, including the /api/cwp prefix on
	// Institutional Vault (e.g. https://vault.example.com/api/cwp).
	CWPBaseURL string `yaml:"cwp_base_url"`

	// APIKey is a cwp_ key issued for the bot user's email.
	// Used only when secret_manager is local. Cloud backends ignore it.
	APIKey string `yaml:"api_key"`

	// APIKeySecretName is the AWS Secrets Manager or Azure Key Vault name
	// for the cwp_ key. Default approver-service-cwp-api-key.
	// CWP_API_KEY_SECRET_NAME overrides it.
	APIKeySecretName string `yaml:"api_key_secret_name"`

	// PrivateKeySecretName is the AWS Secrets Manager or Azure Key Vault
	// name for the signing key. Default approver-service-tls-private-key.
	// CWP_PRIVATE_KEY_SECRET_NAME overrides it.
	PrivateKeySecretName string `yaml:"private_key_secret_name"`

	// PollInterval is a Go duration (default 10s).
	PollInterval string `yaml:"poll_interval"`

	// ConfirmerOnly skips list entries whose InitiatorID does not match
	// this bot user. The bot email is resolved at startup from the API
	// key via IV GET /api/users/info.
	ConfirmerOnly bool `yaml:"confirmer_only"`

	// LogLevel controls zerolog severity (debug, info, warn, error).
	LogLevel string `yaml:"log_level"`
}

func (s ServerConfig) PrivateKeyDecoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PrivateKey)
}

// setup registers the handlers for and adds loggers/middlewares to
// common.echo.Echo
func setup(
	echoInstance *echo.Echo,
	l zerolog.Logger,
) error {
	// Only log errors, not successful requests
	echoInstance.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		LogURI:    true,
		LogStatus: true,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			// Only log request details if there's an error
			if v.Error != nil {
				l.Err(v.Error).
					Str("time", v.StartTime.Format(time.RFC3339)).
					Str("remote_ip", c.RealIP()).
					Str("host", c.Request().Host).
					Str("method", c.Request().Method).
					Str("uri", v.URI).
					Str("user_agent", c.Request().UserAgent()).
					Int("status", v.Status).
					Float64("latency", v.Latency.Seconds()).
					Msg("request")
			}
			return nil
		},
	}))
	echoInstance.Use(middleware.Recover())
	echoInstance.Use(errorMiddleware())

	return nil
}

func (s *Server) Serve() error {
	pollCtx, cancel := context.WithCancel(context.Background())
	s.pollCancel = cancel
	go s.pollLoop(pollCtx)

	err := s.echo.Start(fmt.Sprintf(":%d", s.cfg.Port))
	cancel()
	return err
}

type GetPublicKey struct {
	PublicKey []byte `json:"public_key"`
}

func (s *Server) GetPublicKey(c echo.Context) error {
	return c.JSON(http.StatusOK, &GetPublicKey{
		PublicKey: getPublicKey(s.privateKey),
	})
}

func (s *Server) Health(c echo.Context) error {
	return c.NoContent(http.StatusOK)
}

// checkMakeTransactionIntent is where teams add policy logic before signing.
// MPA stores CWP TransactionIntent JSON under operation type "make transaction"
// (including promoted SignRawTransactionIntent and makeTransaction start requests).
func (s *Server) checkMakeTransactionIntent(intent MakeTransactionIntent, enriched GenericIntent) error {
	if s.checkHook != nil {
		if err := s.checkHook(intent, enriched); err != nil {
			return err
		}
	}
	logEvent := s.logger.Info().
		Str("operation_id", intent.OperationID).
		Str("asset", intent.Asset).
		Str("caip19", intent.CAIP19).
		Str("chain_name", intent.ChainName).
		Bool("test_network", intent.TestNetwork).
		Str("source_master_key", intent.Source.MasterKeyName).
		Str("source_account", intent.Source.AccountName).
		Int("destination_count", len(intent.Destination)).
		Bool("has_raw_tx", intent.RawTransaction != "")

	if intent.Function != nil {
		logEvent = logEvent.Str("function_name", intent.Function.Name)
	}
	if intent.EVM != nil {
		logEvent = logEvent.
			Bool("has_evm_spec", true).
			Str("evm_data", intent.EVM.Data)
	}
	if enriched.IntentMetadata.RateInfo.Rate > 0 {
		logEvent = logEvent.
			Float64("rate", enriched.IntentMetadata.RateInfo.Rate).
			Str("rate_to_currency", enriched.IntentMetadata.RateInfo.ToCurrency)
	}
	if enriched.Initiator.UserID != "" {
		logEvent = logEvent.Str("initiator_id", enriched.Initiator.UserID)
	} else if intent.InitiatorID != "" {
		logEvent = logEvent.Str("initiator_id", intent.InitiatorID)
	}

	logEvent.Msg("evaluating make transaction intent")

	// Example policy hooks (uncomment and adapt for production):
	//
	//   Cap outbound amounts on structured transfers:
	//
	//   const maxAmount = 10_000.0
	//   for _, dest := range intent.Destination {
	//       if dest.Amount == "" { continue }
	//       amount, _ := strconv.ParseFloat(dest.Amount, 64)
	//       if amount > maxAmount {
	//           return fmt.Errorf("amount %s exceeds limit", dest.Amount)
	//       }
	//   }
	//
	//   Whitelist destination addresses or CAIP19 values.
	//   Reject raw-sign when RawTransaction is present but TxHash is empty on Canton.
	//   Note: list payloads have no USD rate metadata (enriched.IntentMetadata.RateInfo
	//   is typically empty); use intent fields directly.

	return nil
}

func parseLogLevel(s string) zerolog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.DebugLevel
	}
}

func getPublicKey(privKey *ecdsa.PrivateKey) []byte {
	// Extract the public key
	publicKey := privKey.PublicKey

	// Convert the public key coordinates (X and Y) to 32-byte slices
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	// Make sure X and Y are exactly 32 bytes long
	xBytesPadded := padTo32Bytes(xBytes)
	yBytesPadded := padTo32Bytes(yBytes)

	// Concatenate the X and Y coordinates to form the 65-byte public key
	// MPA only accepts that format for now
	return slices.Concat(
		[]byte{0x04}, // Prefix 0x04 (indicating the key is uncompressed)
		xBytesPadded,
		yBytesPadded,
	)
}
