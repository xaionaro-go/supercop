package amd64_51_30k

// #cgo CFLAGS: -I/usr/include/sodium
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_sign.h>
import "C"
import (
	"github.com/xaionaro-go/supercop/internal/helpers"
)

// See also: https://nacl.cr.yp.to/sign.html
func CryptoSign(outSignature []byte, inMessage []byte, privKey []byte) {
	C.crypto_sign(
		(*C.uchar)(helpers.BytesToCBytes(outSignature)),
		(*C.ulonglong)(helpers.BytesToLenPointer(outSignature)),
		(*C.uchar)(helpers.BytesToCBytes(inMessage)),
		(C.ulonglong)(len(inMessage)),
		(*C.uchar)(helpers.BytesToCBytes(privKey)),
	)
}
