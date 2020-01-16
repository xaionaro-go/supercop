package helpers

import (
	"reflect"
	"unsafe"
)

func BytesToCBytes(in []byte) unsafe.Pointer {
	return unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&in)).Data)
}

func BytesToLenPointer(in []byte) unsafe.Pointer {
	return unsafe.Pointer(&(*reflect.SliceHeader)(unsafe.Pointer(&in)).Len)
}