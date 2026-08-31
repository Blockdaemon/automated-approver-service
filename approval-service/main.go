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
	"strings"

	"cuelang.org/go/cue/cuecontext"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
	}
}

func loadFromCue(configpath, schemapath string, v interface{}) error {
	// Load in configuration file
	configBytes, err := os.ReadFile(configpath)
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}
	err = formatCueConfigBytes(&configBytes)
	if err != nil {
		return fmt.Errorf("formatting config: %w", err)
	}
	// Load in schema file
	schemaBytes, err := os.ReadFile(schemapath)
	if err != nil {
		return fmt.Errorf("os.ReadFile: %w", err)
	}
	err = formatSchemaBytes(&schemaBytes)
	if err != nil {
		return fmt.Errorf("formatting config: %w", err)
	}

	// Append bytes into a single array representing a new .cue file
	allBytes := append(schemaBytes[:], configBytes...)

	// Compile the bytes - consists of validation and default value evaluation
	ctx := cuecontext.New()
	val := ctx.CompileBytes(allBytes)
	if err := val.Err(); err != nil {
		return fmt.Errorf("cue.Context.CompileBytes: %w", err)
	}
	// Unmarshal data into config
	return val.Value().Decode(v)
}

func formatCueConfigBytes(cb *[]byte) error {
	for i, b := range *cb {
		if b == 35 {
			*cb = (*cb)[i:]
			break
		}
	}
	configString := strings.ReplaceAll(string(*cb), "conf.", "")
	*cb = []byte(configString)
	return nil
}

// formatSchemaBytes appends a byte for a newline character to the end of the schema bytes array
func formatSchemaBytes(sb *[]byte) error {
	*sb = append(*sb, []byte("\n")...)
	return nil
}

func run() error {
	configFile := flag.String(
		"configFile",
		"./infra/config/config_local.cue",
		"path to CUE configuration",
	)
	schemaFile := flag.String(
		"schemaFile",
		"./cue.mod/approval-service/schema.cue",
		"path to CUE schema to validate configFile against",
	)
	genKey := flag.Bool("genkey", false, "print a new P-256 private_key and public_key, then exit")
	once := flag.Bool("once", false, "poll CWP approvals once and exit")
	flag.Parse()

	if *genKey {
		return printGeneratedKey()
	}

	var cfg ServerConfig
	if err := loadFromCue(*configFile, *schemaFile, &cfg); err != nil {
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
