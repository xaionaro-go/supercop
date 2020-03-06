package amd64_51_30k_cgo_test

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	. "github.com/xaionaro-go/supercop/crypto_sign/ed25519/amd64-51-30k_cgo"
)

func TestEd25519AMD64_51_30k_CryptoVerify(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	copy(a, b)
	a[31] = 128
	b[31] = 129
	require.True(t, CryptoVerify32(a, a))
	require.False(t, CryptoVerify32(a, b))
}
