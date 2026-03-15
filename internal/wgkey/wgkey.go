package wgkey

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair creates a WireGuard keypair (Curve25519).
// Returns base64-encoded private and public keys.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", err
	}

	// Clamp private key per WireGuard spec
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(private[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}
