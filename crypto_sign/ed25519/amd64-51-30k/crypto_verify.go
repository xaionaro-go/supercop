package amd64_51_30k

// #cgo CFLAGS: -I/usr/include/sodium
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_verify_32.h>
import "C"
import (
	"fmt"

	"github.com/xaionaro-go/supercop/internal/helpers"
)

func CryptoVerify32(a, b []byte) int {
	if len(a) < 32 {
		panic(fmt.Sprintf("'a' is too short: %d", len(a)))
	}
	if len(b) < 32 {
		panic(fmt.Sprintf("'b' is too short: %d", len(b)))
	}
	// See https://gist.github.com/jfdm/5255788#file-sodium-documented-h-L805
	result := C.crypto_verify_32(
		(*C.uchar)(helpers.BytesToCBytes(a)),
		(*C.uchar)(helpers.BytesToCBytes(b)),
	)
	return int(result)
}
