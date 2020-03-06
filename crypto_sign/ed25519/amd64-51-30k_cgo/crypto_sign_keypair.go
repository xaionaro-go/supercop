package amd64_51_30k_cgo

// #cgo CFLAGS: -I/usr/include/sodium -I c_lib/impl
// #cgo LDFLAGS: -Lc_lib -lamd64_51_30k -lsodium
// #include <crypto_sign.h>
// #include <ge25519.h>
// #include <string.h>
import "C"
import (
	"fmt"
	"io"

	"github.com/xaionaro-go/supercop/internal/helpers"
)

// CryptoSignKeyPair is a port of the SUPERCOP implementation of
// crypto_sign/ed25519/amd64-51-30k:crypto_sign_keypair()
//
// See also: https://nacl.cr.yp.to/sign.html
func CryptoSignKeyPair(outPubKey []byte, outPrivKey []byte, randReader io.Reader) error {
	// "C:" comments are just a reminder of a line from the
	// original SUPERCOP implementation.

	// Checking bounds:
	if len(outPubKey) != PublicKeySize {
		return ErrInvalidPublicKeySize{ReceivedKeySize: uint(len(outPubKey))}
	}
	if len(outPrivKey) != PrivateKeySize {
		return ErrInvalidPrivateKeySize{ReceivedKeySize: uint(len(outPrivKey))}
	}

	// C: unsigned char az[64];
	var az [64]byte
	// C: sc25519 scsk;
	scsk := C.sc25519{}
	// C: ge25519 gepk;
	gepk := C.ge25519{}

	// C: randombytes(sk,32);
	n, err := randReader.Read(outPrivKey[:32])
	if err != nil || n != 32 {
		return fmt.Errorf("unable to read from the random reader (n == %d): %w", n, err)
	}

	// C: crypto_hash_sha512(az,sk,32);
	C.crypto_hash_sha512(
		(*C.uchar)(helpers.BytesToCBytes(az[:])),
		(*C.uchar)(helpers.BytesToCBytes(outPrivKey)),
		32,
	)

	// C: crypto_hash_sha512(az,sk,32);
	C.crypto_hash_sha512(
		(*C.uchar)(helpers.BytesToCBytes(az[:])),
		(*C.uchar)(helpers.BytesToCBytes(outPrivKey[:])),
		32,
	)

	// C: az[0] &= 248;
	az[0] &= 248
	// C: az[31] &= 127;
	az[31] &= 127
	// C: az[31] |= 64;
	az[31] |= 64

	// C: sc25519_from32bytes(&scsk,az);
	C.sc25519_from32bytes(&scsk, (*C.uchar)(helpers.BytesToCBytes(az[:])))

	// C: ge25519_scalarmult_base(&gepk, &scsk);
	C.ge25519_scalarmult_base(&gepk, &scsk)

	// C: ge25519_pack(pk, &gepk);
	C.ge25519_pack((*C.uchar)(helpers.BytesToCBytes(outPubKey[:])), &gepk)

	// C: memmove(sk + 32,pk,32);
	C.memmove(
		helpers.BytesToCBytes(outPrivKey[32:]),
		helpers.BytesToCBytes(outPubKey[:]),
		32,
	)

	return nil
}
