package main

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestAzureSecretName(t *testing.T) {
	require.Equal(t, "sandbox-approval-cwp-api-key", azureSecretName("sandbox-approval-cwp-api-key"))
	require.Equal(t, "sandbox-approval-tls-private-key", azureSecretName("sandbox.approval_tls.private_key"))
}

func TestResolveKeyVaultURL_EnvOverridesConfig(t *testing.T) {
	t.Setenv("AZURE_KEY_VAULT_URI", "https://env.vault.azure.net/")
	require.Equal(t, "https://env.vault.azure.net/", resolveKeyVaultURL("https://cfg.vault.azure.net/"))
}

func TestResolveKeyVaultURL_UsesConfigWhenEnvEmpty(t *testing.T) {
	t.Setenv("AZURE_KEY_VAULT_URI", "")
	require.Equal(t, "https://cfg.vault.azure.net/", resolveKeyVaultURL("https://cfg.vault.azure.net/"))
}

type fakeKeyVault struct {
	value    string
	nilValue bool
	getErr   error
	getName  string
	setName  string
	setVal   string
}

func (f *fakeKeyVault) GetSecret(_ context.Context, name, _ string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.getName = name
	if f.getErr != nil {
		return azsecrets.GetSecretResponse{}, f.getErr
	}
	if f.nilValue {
		return azsecrets.GetSecretResponse{}, nil
	}
	v := f.value
	return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: &v}}, nil
}

func (f *fakeKeyVault) SetSecret(_ context.Context, name string, parameters azsecrets.SetSecretParameters, _ *azsecrets.SetSecretOptions) (azsecrets.SetSecretResponse, error) {
	f.setName = name
	if parameters.Value != nil {
		f.setVal = *parameters.Value
	}
	return azsecrets.SetSecretResponse{}, nil
}

func TestSecretClientAzure_GetAndPut(t *testing.T) {
	fake := &fakeKeyVault{value: "cwp_from_vault"}
	client := &SecretClientAzure{Svc: fake, Logger: zerolog.Nop()}

	got, err := client.GetSecret("sandbox.approval_cwp_api_key")
	require.NoError(t, err)
	require.Equal(t, "cwp_from_vault", got)
	require.Equal(t, "sandbox-approval-cwp-api-key", fake.getName)

	require.NoError(t, client.PutSecret("pem-bytes", "sandbox.approval_tls_private_key"))
	require.Equal(t, "sandbox-approval-tls-private-key", fake.setName)
	require.Equal(t, "pem-bytes", fake.setVal)
}

func TestSecretClientAzure_GetSecretError(t *testing.T) {
	fake := &fakeKeyVault{getErr: errors.New("denied")}
	client := &SecretClientAzure{Svc: fake, Logger: zerolog.Nop()}

	_, err := client.GetSecret("sandbox-approval-cwp-api-key")
	require.ErrorContains(t, err, "denied")
}

func TestSecretClientAzure_NilValue(t *testing.T) {
	fake := &fakeKeyVault{nilValue: true}
	client := &SecretClientAzure{Svc: fake, Logger: zerolog.Nop()}

	_, err := client.GetSecret("sandbox-approval-cwp-api-key")
	require.ErrorContains(t, err, "has no value")
}
