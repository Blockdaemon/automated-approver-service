# Automated Approver Service

Reference implementation for testing CWP fetch-based approvals. The service polls pending operations, ECDSA P-256-signs `make transaction` and `transfer` intents, and posts approve or reject with a `cwp_` API key. Other operation types are skipped. Polling (default `10s`) will later be replaced by CWP WebSocket events (`GET /api/cwp/events`).

Download `automated-approver-service-<os>-<arch>` from [GitHub Releases](https://github.com/Blockdaemon/automated-approver-service/releases) (built on version tags).

## Setup

1. Create a Vault user and add them to the transaction-restriction approver group.
2. Generate a keypair (`./automated-approver-service -genkey`) and register the public key on that user (`GET /public-key` or `-genkey` output).
3. Issue a `cwp_` API key for that user's email. The pending queue is that user's list, not a group inbox.

## Configuration

Local: `infra/config/config_local.cue`. Env overrides CUE and AWS: `CWP_BASE_URL`, `CWP_API_KEY`, `CWP_PRIVATE_KEY`.

| Field | Notes |
| --- | --- |
| `cwp_base_url` | CWP root, including `/api/cwp` on Institutional Vault |
| `api_key` | `cwp_` key. Local: `CWP_API_KEY`. AWS: `sandbox-approval-cwp-api-key` |
| `private_key` | Base64 ASN.1 DER signing key. AWS: `sandbox-approval-tls-private-key` |
| `poll_interval` | Go duration, default `10s` |
| `port` | Local HTTP for `/public-key` and `/health` (default 9294) |
| `secret_manager` | `"local"` or `"secretsmanager"` |

The signature verification key is the uncompressed P-256 public key derived from `private_key`. It is not a secret.

```bash
export CWP_API_KEY='cwp_...'
export CWP_PRIVATE_KEY='...'   # from -genkey
./automated-approver-service -configFile=./infra/config/config_local.cue -once
```

```bash
docker build -f approval-service/Dockerfile -t approval-service:latest .
docker run -p 9294:9294 -v $(pwd)/infra/config:/config \
  approval-service:latest --configFile=/config/config_local.cue
```

## Custom approval checks

Each listed `make transaction` entry is decoded to the stored intent, unmarshaled, passed through `checkMakeTransactionIntent`, then signed. Wallet UI `transfer` operations are signed the same way without that check. Other types are skipped (not rejected).

Customer policy hooks go in `checkMakeTransactionIntent` (`approval-service/server.go`). Return an error to reject via CWP; return `nil` to approve and sign. Do not modify the decoded intent bytes; CWP verifies the signature against the stored intent. List entries do not include EnrichedIntent rate metadata; use fields on `MakeTransactionIntent` (including `InitiatorID`).

The demo check always approves (it only logs). Example: cap outbound amounts on structured transfers (`Destination` populated):

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

This is a reference implementation for testing. The process prints public keys and intent payloads to stdout; do not use as-is in production.
