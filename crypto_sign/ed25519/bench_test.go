package ed25519

import (
	"crypto/ed25519"
	"testing"

	"github.com/xaionaro-go/supercop/internal/testhelpers"
)

func BenchmarkStandardEd25519Sign(b *testing.B) {
	b.ReportAllocs()

	_, privKey, message, _ := testhelpers.GetSignBasics()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(privKey, message)
	}
}
