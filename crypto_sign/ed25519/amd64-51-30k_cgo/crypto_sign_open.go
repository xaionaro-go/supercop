package amd64_51_30k_cgo

// #cgo CFLAGS: -I/usr/include/sodium
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_sign.h>
import "C"
import (
	"math"

	"github.com/xaionaro-go/supercop/internal/helpers"
)

func CryptoSignOpen(outMessage []byte, inSignedMessage []byte, verificationKey []byte) bool {
	if len(inSignedMessage) != len(outMessage)+SignatureSize {
		panic(ErrInvalidSignatureSize{ReceivedKeySize: len(inSignedMessage) - len(outMessage)})
	}
	if len(verificationKey) != PublicKeySize {
		panic(ErrInvalidPublicKeySize{ReceivedKeySize: uint(len(verificationKey))})
	}
	messageLength := uint64(len(outMessage))
	// See https://gist.github.com/jfdm/5255788#file-sodium-documented-h-L341
	result := C.crypto_sign_open(
		(*C.uchar)(helpers.BytesToCBytes(outMessage)),
		(*C.ulonglong)(&messageLength),
		(*C.uchar)(helpers.BytesToCBytes(inSignedMessage)),
		(C.ulonglong)(len(inSignedMessage)),
		(*C.uchar)(helpers.BytesToCBytes(verificationKey)),
	)
	assert(messageLength == uint64(len(outMessage)) || messageLength == math.MaxUint64)
	return result == 0
}
