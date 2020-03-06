package amd64_51_30k_cgo_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/xaionaro-go/supercop/internal/testhelpers"

	. "github.com/xaionaro-go/supercop/crypto_sign/ed25519/amd64-51-30k_cgo"
)

func TestEd25519AMD64_51_30k_CryptoSignKeyPair(t *testing.T) {
	pubKey, privKey := testhelpers.GetKeyStorage()
	require.NoError(t, CryptoSignKeyPair(pubKey, privKey, rand.Reader))
	require.Equal(t, []byte(ed25519.PrivateKey(privKey).Public().(ed25519.PublicKey)), pubKey)

	_, _, message, signedMessageStorage := testhelpers.GetSignBasics()
	CryptoSign(signedMessageStorage, message, privKey)
	restoredMessage := make([]byte, len(message))
	require.True(t, CryptoSignOpen(restoredMessage, signedMessageStorage, pubKey))
	require.Equal(t, message, restoredMessage)
}

func BenchmarkEd25519AMD64_51_30k_CryptoSignKeyPair(b *testing.B) {
	b.ReportAllocs()
	pubKey, privKey := testhelpers.GetKeyStorage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CryptoSignKeyPair(pubKey, privKey, rand.Reader)
	}
}
