package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/rs/zerolog"
)

const (
	SecretsManagerAWS   = "secretsmanager"
	SecretsManagerLocal = "local"
)

// SecretsManagerAPI is an interface defined for unit testing.
type SecretsManagerAPI interface {
	GetSecret(secretName string) (string, error)
	PutSecret(secretValue string, secretName string) error
}

// SecretClientAWS is a client for AWS secret retrieval.
type SecretClientAWS struct {
	Svc    *secretsmanager.Client
	Logger zerolog.Logger
}

type SecretData map[string]interface{}

func NewSecretClientAWS(
	region string,
	l zerolog.Logger,
) (*SecretClientAWS, error) {
	var client SecretClientAWS

	client.Logger = l

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithRegion(region),
	)
	if err != nil {
		client.Logger.Info().
			Msgf("unable to load SDK config, %v", err)
		return nil, err
	}

	client.Svc = secretsmanager.NewFromConfig(cfg)
	return &client, nil
}

func getRegion() string {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if len(region) == 0 {
		return "us-east-1"
	}
	return region
}

func (c *SecretClientAWS) GetSecretContent(content string) (string, error) {
	if c == nil {
		return "", errors.New("unable to create aws client")
	}
	parts := strings.Split(content, "#")

	switch len(parts) {
	case 1:
		secretValue, err := c.GetSecret(parts[0])
		if err != nil {
			return "", fmt.Errorf("AWS secret error: %w", err)
		}
		return secretValue, nil
	case 2:
		secretData, err := c.GetSecret(parts[0])
		if err != nil {
			return "", fmt.Errorf("AWS secret error: %w", err)
		}
		var parsed map[string]interface{}
		json.Unmarshal([]byte(secretData), &parsed)
		val, ok := parsed[parts[1]]
		if !ok {
			return "", fmt.Errorf(
				"key %s not found in secret %s",
				parts[1],
				parts[0],
			)
		}
		c.Logger.Info().
			Msgf("Retrieved aws secret: %v", content)
		return val.(string), nil
	default:
		return "", fmt.Errorf(
			"wrong number of parts in secret %s",
			content,
		)
	}
}

func (c *SecretClientAWS) PutSecret(secretValue string, secretName string) error {
	c.Logger.Info().Msgf("Putting secret %s", secretName)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(secretName),
		SecretString: aws.String(secretValue),
	}
	_, err := c.Svc.PutSecretValue(context.TODO(), input)
	return err
}

func (c *SecretClientAWS) GetSecret(secretName string) (string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	result, err := c.Svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		return "", fmt.Errorf(
			"error getting AWS secret value for secret key %s: %w",
			secretName,
			err,
		)
	}

	return *result.SecretString, nil
}

func (c *SecretClientAWS) GetSecretData(secretName string) (SecretData, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}

	var secretData SecretData

	result, err := c.Svc.GetSecretValue(context.TODO(), input)
	if err != nil {
		return secretData, fmt.Errorf(
			"error getting AWS secret value for secret key %s: %w",
			secretName,
			err,
		)
	}

	var secretString string

	if result.SecretString != nil {
		secretString = *result.SecretString
	}

	err = json.Unmarshal([]byte(secretString), &secretData)
	if err != nil {
		return secretData, fmt.Errorf(
			"error parsing JSON from AWS secret key %s: %w",
			secretName,
			err,
		)
	}

	return secretData, nil
}

// SecretClientLocal secret manager when run locally
type SecretClientLocal struct{}

func NewSecretClientLocal() *SecretClientLocal {
	return &SecretClientLocal{}
}

func (s SecretClientLocal) GetSecret(secretName string) (string, error) {
	return "", nil
}

func (s SecretClientLocal) PutSecret(
	secretValue string,
	secretName string,
) error {
	return nil
}
