package amd64_51_30k_cgo_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xaionaro-go/supercop/internal/testhelpers"

	. "github.com/xaionaro-go/supercop/crypto_sign/ed25519/amd64-51-30k_cgo"
)

func TestEd25519AMD64_51_30k_CryptoSignOpen(t *testing.T) {
	pubKey, privKey, message, signedMessageStorage := testhelpers.GetSignBasics()
	CryptoSign(signedMessageStorage, message, privKey)
	restoredMessage := make([]byte, len(message))
	assert.True(t, CryptoSignOpen(restoredMessage, signedMessageStorage, pubKey))
	assert.Equal(t, message, restoredMessage)
}

func BenchmarkEd25519AMD64_51_30k_CryptoSignOpen(b *testing.B) {
	b.ReportAllocs()
	pubKey, privKey, message, signedMessageStorage := testhelpers.GetSignBasics()

	CryptoSign(signedMessageStorage, message, privKey)
	restoredMessage := make([]byte, len(message))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CryptoSignOpen(restoredMessage, signedMessageStorage, pubKey)
	}
}
