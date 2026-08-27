package main

import (
	conf "github.com/mpa-sandbox-approval-service/config/approval-service"
)

conf.#Config & {
	port: 9294
	private_key: "private_key"
	secret_manager: "secretsmanager"
	cwp_base_url: "https://vault.example.com/api/cwp"
	api_key: "cwp_..."
	poll_interval: "10s"
}
