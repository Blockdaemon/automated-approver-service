package main

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/rs/zerolog"
)

const SecretsManagerAzure = "keyvault"

// azureSecretsAPI is the subset of the Key Vault client used here, so tests
// can substitute a fake.
type azureSecretsAPI interface {
	GetSecret(
		ctx context.Context,
		name string,
		version string,
		options *azsecrets.GetSecretOptions,
	) (azsecrets.GetSecretResponse, error)
	SetSecret(
		ctx context.Context,
		name string,
		parameters azsecrets.SetSecretParameters,
		options *azsecrets.SetSecretOptions,
	) (azsecrets.SetSecretResponse, error)
}

// SecretClientAzure reads and writes secrets in Azure Key Vault.
type SecretClientAzure struct {
	Svc    azureSecretsAPI
	Logger zerolog.Logger
}

func NewSecretClientAzure(vaultURL string, l zerolog.Logger) (*SecretClientAzure, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("azure key vault client: %w", err)
	}
	return &SecretClientAzure{Svc: client, Logger: l}, nil
}

// resolveKeyVaultURL prefers AZURE_KEY_VAULT_URI over the config value.
func resolveKeyVaultURL(cfgURL string) string {
	if v := strings.TrimSpace(os.Getenv("AZURE_KEY_VAULT_URI")); v != "" {
		return v
	}
	return strings.TrimSpace(cfgURL)
}

// azureSecretName maps a logical secret name onto Key Vault's alphabet.
// Vault secret names allow alphanumerics and hyphens, so dots and underscores
// become hyphens.
var azureSecretNamePattern = regexp.MustCompile(`[._]`)

func azureSecretName(secretName string) string {
	return azureSecretNamePattern.ReplaceAllString(secretName, "-")
}

func (c *SecretClientAzure) GetSecret(secretName string) (string, error) {
	name := azureSecretName(secretName)
	resp, err := c.Svc.GetSecret(context.TODO(), name, "", nil)
	if err != nil {
		return "", fmt.Errorf("error getting azure secret %s: %w", name, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("azure secret %s has no value", name)
	}
	c.Logger.Info().Str("secret", name).Msg("retrieved azure secret")
	return *resp.Value, nil
}

func (c *SecretClientAzure) PutSecret(secretValue string, secretName string) error {
	name := azureSecretName(secretName)
	c.Logger.Info().Str("secret", name).Msg("putting azure secret")
	_, err := c.Svc.SetSecret(
		context.TODO(),
		name,
		azsecrets.SetSecretParameters{Value: &secretValue},
		nil,
	)
	if err != nil {
		return fmt.Errorf("error putting azure secret %s: %w", name, err)
	}
	return nil
}
