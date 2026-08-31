package main

import (
	conf "github.com/mpa-sandbox-approval-service/config/approval-service"
)

conf.#Config & {
	port: 9294
	private_key: "private_key"
	secret_manager: "local"
	cwp_base_url: "https://<sandbox>.api.dev.blockdaemon-wallet.com/api/cwp"
	api_key: "cwp_..."
	poll_interval: "10s"
}
