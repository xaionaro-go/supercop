package helpers

import (
	"reflect"
	"unsafe"
)

func bytesHeaders(in []byte) *reflect.SliceHeader {
	return (*reflect.SliceHeader)(unsafe.Pointer(&in))
}

func BytesToCBytes(in []byte) unsafe.Pointer {
	return unsafe.Pointer(bytesHeaders(in).Data)
}

func BytesToLenPointer(in []byte) unsafe.Pointer {
	return unsafe.Pointer(&bytesHeaders(in).Len)
}