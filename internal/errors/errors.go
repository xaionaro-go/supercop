package errors

import (
	"crypto/ed25519"
	"fmt"
)

type InvalidPrivateKeySize struct {
	ReceivedKeySize uint
}
func (err InvalidPrivateKeySize) Error() string {
	return fmt.Sprintf("private key size is invalid %d != %d", err.ReceivedKeySize, ed25519.PrivateKeySize)
}

type InvalidPublicKeySize struct {
	ReceivedKeySize uint
}
func (err InvalidPublicKeySize) Error() string {
	return fmt.Sprintf("public key size is invalid %d != %d", err.ReceivedKeySize, ed25519.PublicKeySize)
}

type InvalidSignatureSize struct {
	ReceivedKeySize int
}
func (err InvalidSignatureSize) Error() string {
	return fmt.Sprintf("public key size is invalid %d != %d", err.ReceivedKeySize, ed25519.SignatureSize)
}
