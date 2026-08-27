package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ECDSASignature holds the ASN.1 structure for ECDSA signatures (r, s)
type ECDSASignature struct {
	R, S *big.Int
}

// Encode ECDSA (r, s) signature
func signIntent(
	privateKey *ecdsa.PrivateKey,
	intent []byte,
) ([]byte, error) {
	hash := sha256.Sum256(intent)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, err
	}

	sig := ECDSASignature{
		R: r,
		S: s,
	}

	return asn1.Marshal(sig)
}

// Helper function to pad a byte slice to 32 bytes
func padTo32Bytes(b []byte) []byte {
	if len(b) == 32 {
		return b
	}

	// Create a new slice of 32 bytes and copy the original bytes to the rightmost part
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func verifySignature(message, publicKey, signature []byte) error {
	pk, err := x963PublicKeyToECDSAPublicKey(publicKey)
	if err != nil {
		return err
	}

	h := sha256.New()
	h.Write(message)
	digest := h.Sum(nil)

	if !ecdsa.VerifyASN1(pk, digest, signature) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

func x963PublicKeyToECDSAPublicKey(publicKey []byte) (*ecdsa.PublicKey, error) {
	if len(publicKey) != 65 {
		return nil, fmt.Errorf(
			"public key len expected 65, got %d. Base64 key: %s",
			len(publicKey), base64.StdEncoding.EncodeToString(publicKey),
		)
	}
	if publicKey[0] != 4 {
		return nil, fmt.Errorf("not an uncompressed public key")
	}

	x := new(big.Int).SetBytes(publicKey[1:33])
	y := new(big.Int).SetBytes(publicKey[33:65])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid public key")
	}

	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, fmt.Errorf("point at infinity cannot be a public key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}
