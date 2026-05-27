package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const operationTypeMakeTransaction = "make transaction"

// Server hosts the HTTP API for the automated approver service.
// It exposes endpoints that MPA can call to obtain an approval signature
// for a given enriched intent.
//
// This is a reference implementation for testing. Extend checkMakeTransactionIntent
// with your own policy rules before any production use.
type Server struct {
	echo   *echo.Echo
	logger zerolog.Logger

	cfg ServerConfig

	tlsCert    *tls.Certificate
	privateKey *ecdsa.PrivateKey
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
			return nil, fmt.Errorf("failed to get tls private key: %s", err)
		}

		cfg.TLSPrivateKeySeed, err = secretManager.GetSecret("sandbox-approval-key-seed")
		if err != nil {
			return nil, fmt.Errorf("failed to get key seed: %s", err)
		}
	}

	var tlsCert *tls.Certificate
	if cfg.TLSPrivateKeySeed != "" {
		decodedSeed, err := cfg.TLSPrivateKeySeedDecoded()
		if err != nil {
			return nil, fmt.Errorf("failed to decode tls private key: %s", err)
		}

		cert, err := selfSignedTLSCertificateFromSeed(lgr, decodedSeed, secretManager)
		if err != nil {
			return nil, fmt.Errorf("failed to create tls certificate: %s", err)
		}
		tlsCert = &cert
	}

	privateKeyDer, err := cfg.PrivateKeyDecoded()
	if err != nil {
		return nil, fmt.Errorf("failed to decode pk: %s", err)
	}
	privateKey, err := x509.ParseECPrivateKey(privateKeyDer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pk: %s", err)
	}

	publicKey := base64.StdEncoding.EncodeToString(
		getPublicKey(privateKey),
	)
	fmt.Printf("signature_verification_key\":\"%s\"\n", publicKey)

	err = secretManager.PutSecret(
		publicKey,
		"sandbox-approval-signature-verification-key",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to put aws secret sandbox-approval-signature-verification-key: %s", err)
	}

	server := Server{
		cfg:        cfg,
		echo:       echoInstance,
		logger:     lgr,
		privateKey: privateKey,
		tlsCert:    tlsCert,
	}

	// Routes
	echoInstance.POST("/confirm", server.Confirm)
	echoInstance.GET("/public-key", server.GetPublicKey)

	return &server, nil
}

type ServerConfig struct {
	Port int `json:"port"`

	// ASN.1 DER encoded private key
	PrivateKey string `json:"private_key"`

	// TLSPrivateKeySeed A base64 32-byte seed key which will be used for
	// TLS certificate creation
	TLSPrivateKeySeed string `json:"tls_private_key_seed"`

	SecretManager string `json:"secret_manager"`
}

func (s ServerConfig) PrivateKeyDecoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PrivateKey)
}

func (s ServerConfig) TLSPrivateKeySeedDecoded() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.TLSPrivateKeySeed)
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
	// Running TLS if cert is available
	if s.tlsCert != nil {
		server := http.Server{
			Addr:      fmt.Sprintf(":%d", s.cfg.Port),
			Handler:   s.echo, // set Echo as handler
			TLSConfig: newTLSConfig(*s.tlsCert),
		}

		// TLS server started, no need to log port
		err := server.ListenAndServeTLS("", "")
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}

	// Server started, no need to log port
	return s.echo.Start(fmt.Sprintf(":%d", s.cfg.Port))
}

type SignOperationRequest struct {
	EnrichedIntent []byte
	MPASignature   []byte
}

func (s SignOperationRequest) Validate() error {
	return validation.ValidateStruct(&s,
		validation.Field(&s.EnrichedIntent, validation.Required),
		// TODO: Uncomment this when MPA is updated to require the signature
		//validation.Field(&s.MPASignature, validation.Required),
	)
}

type SignOperationResponse struct {
	Confirmed bool
	Signature []byte
}

// Confirm is the main entry point used by MPA to request an approval.
// The flow is:
//  1. Bind and validate the request payload.
//  2. Decode the enriched intent into a GenericIntent wrapper.
//  3. Run checkMakeTransactionIntent against the inner TransactionIntent JSON.
//  4. If checks pass, sign the raw intent bytes and return the signature.
func (s *Server) Confirm(c echo.Context) error {
	var body SignOperationRequest
	if err := c.Bind(&body); err != nil {
		s.logger.Error().
			Err(err).
			Msg("failed to bind SignOperationRequest")
		return err
	}

	if err := body.Validate(); err != nil {
		return err
	}

	var genericIntent GenericIntent

	// EnrichedIntent is a generic wrapper which contains the actual intent
	// under GenericIntent.Intent and some metadata (rate info, initiator, etc).
	if err := json.Unmarshal(body.EnrichedIntent, &genericIntent); err != nil {
		s.logger.Error().
			Err(err).
			RawJSON("enriched_intent", body.EnrichedIntent).
			Msg("failed to unmarshal EnrichedIntent into GenericIntent")
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if genericIntent.OperationType != operationTypeMakeTransaction {
		s.logger.Warn().
			Str("operationType", genericIntent.OperationType).
			RawJSON("intent", genericIntent.Intent).
			Msg("unsupported operation type requested")
		return echo.NewHTTPError(
			http.StatusNotImplemented,
			"unsupported operation type: "+genericIntent.OperationType+
				" (this reference service only handles "+operationTypeMakeTransaction+")",
		)
	}

	var makeTxIntent MakeTransactionIntent
	if err := json.Unmarshal(genericIntent.Intent, &makeTxIntent); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	if err := s.checkMakeTransactionIntent(makeTxIntent, genericIntent); err != nil {
		s.logger.Warn().
			Err(err).
			Str("operationType", genericIntent.OperationType).
			RawJSON("intent", genericIntent.Intent).
			Msg("make transaction intent did not pass automated checks")
		return echo.NewHTTPError(http.StatusForbidden, err.Error())
	}

	intentJSON, _ := json.MarshalIndent(makeTxIntent, "", "  ")
	fmt.Printf("\n=== MAKE TRANSACTION INTENT ===\n%s\n", string(intentJSON))

	if strings.EqualFold(makeTxIntent.Asset, "CC") && makeTxIntent.RawTransaction != "" {
		if decoded, err := decodeProtoWireFromBase64(makeTxIntent.RawTransaction); err != nil {
			s.logger.Warn().Err(err).Msg("failed to decode CC RawTransaction as protobuf wire format")
		} else if decodedJSON, err := json.MarshalIndent(decoded, "", "  "); err == nil {
			fmt.Printf("\n=== DECODED RAW TX (PROTO WIRE, CC) ===\n%s\n", string(decodedJSON))
		}
	}

	signature, err := signIntent(s.privateKey, genericIntent.Intent)
	if err != nil {
		s.logger.Error().
			Err(err).
			RawJSON("intent", genericIntent.Intent).
			Msg("failed to sign intent")
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Print signature information
	signatureB64 := base64.StdEncoding.EncodeToString(signature)
	fmt.Printf("\n=== SIGNATURE (APPROVED) ===\n")
	fmt.Printf("Signature (Base64): %s\n", signatureB64)
	fmt.Printf("Signature (Hex): %x\n", signature)
	fmt.Printf("========================\n\n")

	return c.JSON(
		http.StatusOK,
		&SignOperationResponse{
			Confirmed: true,
			Signature: signature,
		},
	)
}

type GetPublicKey struct {
	PublicKey []byte `json:"public_key"`
}

func (s *Server) GetPublicKey(c echo.Context) error {
	return c.JSON(http.StatusOK, &GetPublicKey{
		PublicKey: getPublicKey(s.privateKey),
	})
}

// checkMakeTransactionIntent is where teams add policy logic before signing.
// MPA stores CWP TransactionIntent JSON under operation type "make transaction"
// (including promoted SignRawTransactionIntent and makeTransaction start requests).
func (s *Server) checkMakeTransactionIntent(intent MakeTransactionIntent, enriched GenericIntent) error {
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

func newTLSConfig(cert tls.Certificate) *tls.Config {
	tlsConfig := tls.Config{
		MinVersion: uint16(tls.VersionTLS12),
		MaxVersion: uint16(tls.VersionTLS13),
		CipherSuites: []uint16{
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}

	return &tlsConfig
}
