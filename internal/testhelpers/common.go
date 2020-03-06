package testhelpers

import (
	"crypto/ed25519"
	"crypto/rand"
)

func GetSignBasics() ([]byte, []byte, []byte, []byte) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	message := []byte("hello world!")
	signatureStorage := make([]byte, ed25519.SignatureSize)
	return pubKey, privKey, message, signatureStorage
}

func GetKeyStorage() ([]byte, []byte) {
	pubKey := make([]byte, ed25519.PublicKeySize)
	privKey := make([]byte, ed25519.PrivateKeySize)
	return pubKey, privKey
}