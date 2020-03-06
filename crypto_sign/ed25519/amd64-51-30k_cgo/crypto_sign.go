package amd64_51_30k_cgo

// #cgo CFLAGS: -I/usr/include/sodium
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_sign.h>
import "C"
import (
	"github.com/xaionaro-go/supercop/internal/helpers"
)

// Just a wrapper around "C.crypto_sign()"
// See also: https://nacl.cr.yp.to/sign.html
func CryptoSign(outSignedMessage []byte, inMessage []byte, privKey []byte) {
	if len(outSignedMessage) < len(inMessage)+SignatureSize {
		panic(ErrInvalidSignatureSize{ReceivedKeySize: len(outSignedMessage) - len(inMessage)})
	}
	if len(privKey) != PrivateKeySize {
		panic(ErrInvalidPrivateKeySize{ReceivedKeySize: uint(len(privKey))})
	}
	sigLength := uint64(len(outSignedMessage))
	C.crypto_sign(
		(*C.uchar)(helpers.BytesToCBytes(outSignedMessage)),
		(*C.ulonglong)(&sigLength),
		(*C.uchar)(helpers.BytesToCBytes(inMessage)),
		(C.ulonglong)(len(inMessage)),
		(*C.uchar)(helpers.BytesToCBytes(privKey)),
	)
	assert(sigLength <= uint64(len(outSignedMessage)))
}
