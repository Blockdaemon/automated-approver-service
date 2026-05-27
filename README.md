# Institutional Vault Automated Approver Service - Reference Implementation

## Overview

The Automated Approver Service is a lightweight approval server and **reference implementation for testing** MPC Policy Authority (MPA) approval workflows. It signs `make transaction` intents (MPA `TransactionIntent` JSON) with ECDSA P-256.

CWP routes such as `POST /api/cwp/operations/start/makeTransaction` store this shape.

## Features

- **Intent approval**: Signs `make transaction` enriched intents from MPA
- **Cryptographic signing**: ECDSA P-256 signature over the inner intent bytes
- **TLS support**: Optional TLS with Ed25519 certificates
- **Chain parameters**: Top-level `EVM`, `Canton`, and related fields (promoted `ChainParameters`, not a nested `BlockchainSpec` object)
- **AWS integration**: Secrets Manager integration

### Components

1. **Approval Server** (`approval-service/`): Core Go service that handles approval requests
2. **Infrastructure** (`infra/`): Service configuration files
3. **Configuration** (`cue.mod/`): CUE schemas for configuration validation

## Prerequisites

- Go 1.23 or higher
- Docker (optional, for containerized deployment)

## Configuration

For local development, configure via `infra/config/config_local.cue`:

- `port`: Server port (default: 9294)
- `private_key`: Base64-encoded ASN.1 DER private key for signing https://go.dev/play/p/hvTalsJgu2T
- `tls_private_key_seed`: Base64-encoded 32-byte seed for TLS certificate https://go.dev/play/p/t7OAtd0-ilL
- `secret_manager`: Use `"local"` for local development

Otherwise, use AWS Secrets Manager:

Required secrets names:

- `sandbox-approval-tls-private-key`: TLS private key
- `sandbox-approval-key-seed`: TLS certificate seed
- `sandbox-approval-tls-public-key`: TLS public key (auto-generated)
- `sandbox-approval-signature-verification-key`: Signature verification key (auto-generated)

## Deployment

Build and run the container:

```bash
docker build -f approval-service/Dockerfile -t approval-service:latest .
docker run -p 9294:9294 \
  -v $(pwd)/infra/config:/config \
  approval-service:latest \
  --configFile=/config/config_local.cue
```

The service will start on `http://localhost:9294`.

## API Endpoints

### POST /confirm

Approves and signs a transaction intent when `EnrichedIntent.OperationType` is `make transaction`.

**Request:**

```json
{
  "EnrichedIntent": "<base64-encoded-intent-bytes>",
  "MPASignature": "<base64-encoded-signature-bytes>"
}
```

**Response:**

```json
{
  "Confirmed": true,
  "Signature": "<base64-encoded-signature-bytes>"
}
```

### GET /public-key

Returns the server's public key for signature verification.

**Response:**

```json
{
  "public_key": "<65-byte-uncompressed-public-key>"
}
```

## Custom approval logic

`POST /confirm` unmarshals the enriched intent, runs `checkMakeTransactionIntent`, and only then signs `genericIntent.Intent` (the inner JSON exactly as MPA stored it).

Extend `checkMakeTransactionIntent` in `approval-service/server.go`. Return an error to reject (HTTP 403); return `nil` to allow signing.

Example: cap outbound amounts on structured transfers (non-raw-sign intents with `Destination` populated):

```go
func (s *Server) checkMakeTransactionIntent(intent MakeTransactionIntent, enriched GenericIntent) error {
	const maxAmount = 10_000.0

	for _, dest := range intent.Destination {
		if dest.Amount == "" {
			continue
		}
		amount, err := strconv.ParseFloat(dest.Amount, 64)
		if err != nil {
			return fmt.Errorf("invalid amount %q: %w", dest.Amount, err)
		}
		notional := amount
		if enriched.IntentMetadata.RateInfo.Rate > 0 {
			notional = amount * enriched.IntentMetadata.RateInfo.Rate
		}
		if notional > maxAmount {
			return fmt.Errorf("amount %s exceeds limit", dest.Amount)
		}
	}
	return nil
}
```

`Confirm` calls the check before signing:

```go
if err := s.checkMakeTransactionIntent(makeTxIntent, genericIntent); err != nil {
	return echo.NewHTTPError(http.StatusForbidden, err.Error())
}
signature, err := signIntent(s.privateKey, genericIntent.Intent)
```

Do not modify `genericIntent.Intent` after checks pass; the signature must match MPA's stored bytes.

## Security considerations

**Important:** This is a **reference implementation for testing**. Harden it before production use.

- The demo `checkMakeTransactionIntent` approves every request (it only logs context).
- **Private signing keys are not written to logs**, but the reference server prints **public** material and request payloads to stdout for debugging:
  - At startup: base64 signature verification public key (`newServer`).
  - On each approval: full intent JSON, optional decoded Canton raw tx, and the produced signature (`fmt.Printf` in `Confirm`).
- Failed checks may log the intent via structured logging (`RawJSON("intent", ...)`).
- Remove or gate debug `fmt.Printf` output in production deployments.
