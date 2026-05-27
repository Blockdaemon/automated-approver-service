package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignAndVerifySignature(t *testing.T) {
	// Minimal make transaction / TransactionIntent-shaped JSON for signIntent round-trip.
	intent, err := base64.StdEncoding.DecodeString("eyJPcGVyYXRpb25UeXBlIjoibWFrZSB0cmFuc2FjdGlvbiIsIk9wZXJhdGlvbklEIjoib3AtdGVzdCIsIkFzc2V0IjoiRVRIIiwiVGVzdE5ldHdvcmsiOnRydWUsIlNvdXJjZSI6eyJNYXN0ZXJLZXlOYW1lIjoiRGVmYXVsdCIsIkFjY291bnROYW1lIjoiYWNjMSJ9LCJEZXN0aW5hdGlvbiI6W3siQWRkcmVzcyI6IjB4YWIiLCJBbW91bnQiOiIwLjAwMSJ9XX0=")
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signature, err := signIntent(privateKey, intent)
	require.NoError(t, err)

	err = verifySignature(intent, getPublicKey(privateKey), signature)
	require.NoError(t, err)
}
