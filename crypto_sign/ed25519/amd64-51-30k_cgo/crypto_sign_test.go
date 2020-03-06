package amd64_51_30k_cgo_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/stretchr/testify/assert"
	. "github.com/xaionaro-go/supercop/crypto_sign/ed25519/amd64-51-30k_cgo"
	"github.com/xaionaro-go/supercop/internal/testhelpers"
)

func TestEd25519AMD64_51_30k_CryptoSign(t *testing.T) {
	_, privKey, message, signedMessageStorage := testhelpers.GetSignBasics()
	CryptoSign(signedMessageStorage, message, privKey)
	assert.Equal(t, ed25519.Sign(privKey, message), signedMessageStorage[:ed25519.SignatureSize])
}

func BenchmarkEd25519AMD64_51_30k_CryptoSign(b *testing.B) {
	b.ReportAllocs()

	_, privKey, message, signedMessageStorage := testhelpers.GetSignBasics()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CryptoSign(signedMessageStorage, message, privKey)
	}
}
