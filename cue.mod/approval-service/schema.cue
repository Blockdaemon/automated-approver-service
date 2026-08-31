package approval_service

#Config: {
	port:         				uint32 & >=0 & <=65535 | *9294
	// base64 ASN.1 DER encoded private key
	// Example key generation: https://go.dev/play/p/hvTalsJgu2T
	private_key:  				string

	secret_manager: "secretsmanager" | *"local"

	// CWP approvals root, including /api/cwp on Institutional Vault.
	// Example: "https://vault.example.com/api/cwp"
	cwp_base_url: string

	// cwp_ API key issued for the bot user's email. Local only; with
	// secret_manager: "secretsmanager" the key is read from
	// sandbox-approval-cwp-api-key.
	api_key: string | *""

	// Go duration between list polls. Polling will be replaced by CWP
	// WebSocket events in a later change.
	poll_interval: string | *"10s"
}