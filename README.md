# Automated Approver Service

Reference implementation for testing CWP fetch-based approvals. The service polls pending operations, ECDSA P-256-signs `make transaction` and `transfer` intents, and posts approve or reject with a `cwp_` API key. Other operation types are skipped. 

Download `automated-approver-service-<os>-<arch>` from [GitHub Releases](https://github.com/Blockdaemon/automated-approver-service/releases).

## Setup

1. Create a Vault user and add them to the transaction-restriction approver group.
2. Generate a keypair (`./automated-approver-service -genkey`) and register the public key on that user (`GET /public-key` or `-genkey` output).
3. Issue a `cwp_` API key for that user's email. The pending queue is that user's list, not a group inbox.



## Configuration

Copy `[config.yaml](config.yaml)` and fill in `cwp_base_url`, `api_key`, and `private_key`. Env overrides the file: `CWP_BASE_URL`, `CWP_API_KEY`, `CWP_PRIVATE_KEY`, `CWP_CONFIRMER_ONLY`, `CWP_LOG_LEVEL`, `AZURE_KEY_VAULT_URI`. With `secret_manager: secretsmanager` or `secret_manager: keyvault`, the API key and private key come from AWS Secrets Manager or Azure Key Vault (`sandbox-approval-cwp-api-key`, `sandbox-approval-tls-private-key`) instead of the file. Key Vault auth uses the Azure default credential chain.


| Field            | Env                  | Notes                                                                                                            |
| ---------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `cwp_base_url`   | `CWP_BASE_URL`       | CWP root, including `/api/cwp` on Institutional Vault                                                            |
| `api_key`        | `CWP_API_KEY`        | `cwp_` key. Secret name: `sandbox-approval-cwp-api-key`                                                          |
| `private_key`    | `CWP_PRIVATE_KEY`    | Base64 ASN.1 DER signing key. Secret name: `sandbox-approval-tls-private-key`                                    |
| `poll_interval`  |                      | Go duration, default `10s`                                                                                       |
| `port`           |                      | Local HTTP for `/public-key` and `/health` (default 9294)                                                        |
| `secret_manager` |                      | `local`, `secretsmanager` (AWS), or `keyvault` (Azure Key Vault)                                                 |
| `key_vault_url`  | `AZURE_KEY_VAULT_URI`| Vault URI when `secret_manager` is `keyvault`, for example `https://example.vault.azure.net/`                    |
| `confirmer_only` | `CWP_CONFIRMER_ONLY` | When true, only confirm/approve entries initiated by self (default false)                                        |
| `log_level`      | `CWP_LOG_LEVEL`      | `debug` (default), `info`, `warn`, `error`. Debug enables console output with intent dumps; info+ uses JSON logs |


The signature verification key is the uncompressed P-256 public key derived from `private_key`. It is not a secret.

### Confirmer-only mode

When `confirmer_only` is true, the service only confirms or approves list entries whose `InitiatorID` matches the bot user email (case-insensitive). Other entries are silently skipped - not rejected - so another approver or human can still act on them.

This is useful when the bot is the **initiator** and the policy requires the initiator to confirm their own operation before other approvers are asked.

```bash
export CWP_API_KEY='cwp_...'
export CWP_PRIVATE_KEY='...'   # from -genkey
./automated-approver-service -configFile=./config.yaml -once
```



## Custom approval checks

Each listed `make transaction` entry is decoded to the stored intent, unmarshaled, passed through `checkMakeTransactionIntent`, then signed. Wallet UI `transfer` operations are signed the same way without that check. Other types are skipped (not rejected).

Custom policy hooks go in `checkMakeTransactionIntent` (`approval-service/server.go`). Return an error to reject via CWP; return `nil` to approve and sign.

The default behavior is always-approve (no checks). Production policy belongs in the `checkMakeTransactionIntent` hook.

Example - cap outbound amounts on structured transfers (`Destination` populated):

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



## Production Usage

This is a reference implementation for testing. In debug mode the process prints intent payloads and signatures to stdout; set `log_level: "info"` or higher for production use.