package amd64_51_30k_cgo

// #cgo CFLAGS: -I/usr/include/sodium
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_sign.h>
// #include "./c_lib/impl/api.h"
import "C"

const (
	PrivateKeySize = C.CRYPTO_SECRETKEYBYTES
	PublicKeySize  = C.CRYPTO_PUBLICKEYBYTES
	SignatureSize  = C.CRYPTO_BYTES
)
