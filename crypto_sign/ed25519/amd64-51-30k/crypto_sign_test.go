package amd64_51_30k_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	amd64_51_30k "github.com/xaionaro-go/supercop/crypto_sign/ed25519/amd64-51-30k"
)

func getBasics() ([]byte, []byte, []byte) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	message := []byte("hello world!")
	signature := make([]byte, ed25519.SignatureSize)
	return privKey, message, signature
}

func TestCryptoSign(t *testing.T) {
	privKey, message, signatureStorage := getBasics()
	amd64_51_30k.CryptoSign(signatureStorage, message, privKey)
	assert.Equal(t, ed25519.Sign(privKey, message), signatureStorage)
}

func BenchmarkCryptoSign(b *testing.B) {
	b.ReportAllocs()

	privKey, message, signatureStorage := getBasics()
	b.ResetTimer()
	for i:=0; i<b.N; i++ {
		amd64_51_30k.CryptoSign(signatureStorage, message, privKey)
	}
}

func BenchmarkGoEd25519Sign(b *testing.B) {
	b.ReportAllocs()

	privKey, message, _ := getBasics()
	b.ResetTimer()
	for i:=0; i<b.N; i++ {
		ed25519.Sign(privKey, message)
	}
}