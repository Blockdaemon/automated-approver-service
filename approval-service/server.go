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
	"github.com/rs/zerolog/log"
)

const operationTypeMakeTransaction = "make transaction"
const operationTypeTransfer = "transfer"

// Server polls CWP for pending approvals and signs make-transaction intents.
// GET /public-key remains for registering the ECDSA P-256 key on the bot user.
//
// This is a reference implementation for testing. Extend checkMakeTransactionIntent
// with your own policy rules before any production use.
type Server struct {
	echo   *echo.Echo
	logger zerolog.Logger

	cfg ServerConfig

	privateKey   *ecdsa.PrivateKey
	cwp          approvalAPI
	pollInterval time.Duration
	pollCancel   context.CancelFunc
	checkHook    func(MakeTransactionIntent, GenericIntent) error
}

func newServer(cfg ServerConfig) (*Server, error) {
	echoInstance := echo.New()
	echoInstance.HideBanner = true

	lgr := log.Logger.With().
		Str("component", "system-approver-test").
		Logger()

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
	case SecretsManagerLocal:
		secretManager = NewSecretClientLocal()
	default:
		return nil, fmt.Errorf("secret manager type %s is not supported", cfg.SecretManager)
	}

	if cfg.SecretManager != SecretsManagerLocal {
		cfg.PrivateKey, err = secretManager.GetSecret("sandbox-approval-tls-private-key")
		if err != nil {
			return nil, fmt.Errorf("failed to get signing private key: %s", err)
		}

		cfg.APIKey, err = secretManager.GetSecret("sandbox-approval-cwp-api-key")
		if err != nil {
			return nil, fmt.Errorf("failed to get cwp api key: %s", err)
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

	privateKeyDer, err := cfg.PrivateKeyDecoded()
	if err != nil {
		return nil, fmt.Errorf("failed to decode pk: %s", err)
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pk: %s", err)
	}

	fmt.Printf("signature_verification_key\":\"%s\"\n",
		base64.StdEncoding.EncodeToString(getPublicKey(privateKey)))

	if strings.TrimSpace(cfg.CWPBaseURL) == "" {
		return nil, fmt.Errorf("cwp_base_url is required")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, fmt.Errorf("api_key is required (CWP_API_KEY, config api_key, or sandbox-approval-cwp-api-key)")
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

	server := Server{
		cfg:          cfg,
		echo:         echoInstance,
		logger:       lgr,
		privateKey:   privateKey,
		cwp:          newCWPClient(cfg.CWPBaseURL, cfg.APIKey),
		pollInterval: pollInterval,
	}

	echoInstance.GET("/public-key", server.GetPublicKey)
	echoInstance.GET("/health", server.Health)

	return &server, nil
}

type ServerConfig struct {
	Port int `json:"port"`

	// ASN.1 DER encoded private key
	PrivateKey string `json:"private_key"`

	SecretManager string `json:"secret_manager"`

	// CWPBaseURL is the CWP approvals root, including the /api/cwp prefix on
	// Institutional Vault (e.g. https://vault.example.com/api/cwp).
	CWPBaseURL string `json:"cwp_base_url"`

	// APIKey is a cwp_ key issued for the bot user's email.
	APIKey string `json:"api_key"`

	// PollInterval is a Go duration (default 10s).
	PollInterval string `json:"poll_interval"`
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

	// Example policy hooks:
	//   - Parse intent.Destination[i].Amount and compare to limits
	//   - Whitelist destination addresses or CAIP19 values
	//   - Reject raw-sign when RawTransaction is present but TxHash is empty on Canton
	//   - Use enriched.IntentMetadata.RateInfo for USD notional caps

	return nil
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
