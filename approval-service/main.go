package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}

func loadConfig(path string) (ServerConfig, error) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, fmt.Errorf("read config: %w", err)
	}

	var cfg ServerConfig
	if err := yaml.Unmarshal(configBytes, &cfg); err != nil {
		return ServerConfig{}, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

func (c *ServerConfig) applyDefaults() {
	if c.Port == 0 {
		c.Port = 9294
	}
	if c.SecretManager == "" {
		c.SecretManager = SecretsManagerLocal
	}
	if c.PollInterval == "" {
		c.PollInterval = "10s"
	}
	if c.LogLevel == "" {
		c.LogLevel = "debug"
	}
}

func (c ServerConfig) validate() error {
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("port must be between 0 and 65535")
	}
	switch c.SecretManager {
	case SecretsManagerLocal, SecretsManagerAWS, SecretsManagerAzure:
	default:
		return fmt.Errorf("secret_manager must be %q, %q, or %q", SecretsManagerLocal, SecretsManagerAWS, SecretsManagerAzure)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be debug, info, warn, or error")
	}
	return nil
}

func run() error {
	configFile := flag.String(
		"configFile",
		"./config.yaml",
		"path to YAML configuration",
	)
	genKey := flag.Bool("genkey", false, "print a new P-256 private_key and public_key, then exit")
	once := flag.Bool("once", false, "poll CWP approvals once and exit")
	flag.Parse()

	if *genKey {
		return printGeneratedKey()
	}

	cfg, err := loadConfig(*configFile)
	if err != nil {
		return err
	}

	server, err := newServer(cfg)
	if err != nil {
		return err
	}

	if *once {
		return server.pollOnce(context.Background())
	}

	if err := server.Serve(); err != nil {
		return fmt.Errorf("server error: %s", err)
	}

	return nil
}

func printGeneratedKey() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	priv := base64.StdEncoding.EncodeToString(der)
	pub := base64.StdEncoding.EncodeToString(getPublicKey(key))
	fmt.Printf("CWP_PRIVATE_KEY / config private_key:\n%s\n\n", priv)
	fmt.Printf("setUserPublicKey PublicKey (65-byte uncompressed, base64):\n%s\n", pub)
	return nil
}
