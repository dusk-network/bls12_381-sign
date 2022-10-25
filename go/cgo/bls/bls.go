// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

package bls

// #cgo darwin,!arm64 LDFLAGS: -L./ -ldusk_bls12_381_sign_ffi_macos-latest -ldl -lm
// #cgo darwin,arm64 LDFLAGS: -L./ -ldusk_bls12_381_sign_ffi_macos-latest_arm -ldl -lm
// #cgo linux,!arm64 LDFLAGS: -L./ -ldusk_bls12_381_sign_ffi_ubuntu-latest -ldl -lm
// #cgo linux,arm64 LDFLAGS: -L./ -ldusk_bls12_381_sign_ffi_ubuntu-latest_arm -ldl -lm
// #include "./libbls.h"
import "C"

import (
	"errors"
	"unsafe"
)

func GenerateKeys() ([]byte, []byte) {
	skBuf := make([]byte, C.SK_SIZE)
	pkBuf := make([]byte, C.PK_SIZE)

	sk_ptr := toPtr(skBuf)
	pk_ptr := toPtr(pkBuf)

	C.generate_keys(sk_ptr, pk_ptr)
	return skBuf, pkBuf
}

func GenerateKeysWithRaw() ([]byte, []byte, []byte) {
	skBuf := make([]byte, C.SK_SIZE)
	pkBuf := make([]byte, C.PK_SIZE)
	pkBufRaw := make([]byte, C.PK_RAW_SIZE)

	sk_ptr := toPtr(skBuf)
	pk_ptr := toPtr(pkBuf)
	pk_raw_ptr := toPtr(pkBufRaw)

	C.generate_keys_with_raw(sk_ptr, pk_ptr, pk_raw_ptr)
	return skBuf, pkBuf, pkBufRaw
}

func Sign(sk, pk, msg []byte) ([]byte, error) {
	sk_ptr := toPtr(sk)
	pk_ptr := toPtr(pk)
	msg_ptr := toPtr(msg)
	sigBuf := make([]byte, C.SIG_SIZE)
	sig_ptr := toPtr(sigBuf)
	code := C.sign(sk_ptr, pk_ptr, msg_ptr, C.size_t(len(msg)), sig_ptr)
	return sigBuf, formatErr(code)
}

func Verify(apk, sig, msg []byte) error {
	apk_ptr := toPtr(apk)
	sig_ptr := toPtr(sig)
	msg_ptr := toPtr(msg)
	code := C.verify(apk_ptr, sig_ptr, msg_ptr, C.size_t(len(msg)))
	return formatErr(code)
}

func CreateApk(pk []byte) ([]byte, error) {
	pk_ptr := toPtr(pk)
	apkBuf := make([]byte, C.PK_SIZE)
	apk_ptr := toPtr(apkBuf)
	code := C.create_apk(pk_ptr, apk_ptr)
	return apkBuf, formatErr(code)
}

func AggregatePk(apk []byte, pks ...[]byte) ([]byte, error) {
	apk_ptr := toPtr(apk)
	pkBytes := make([]byte, 0)
	for _, pk := range pks {
		pkBytes = append(pkBytes, pk...)
	}

	pk_ptr := toPtr(pkBytes)
	retBuf := make([]byte, C.PK_SIZE)
	ret_ptr := toPtr(retBuf)
	code := C.aggregate_pk(apk_ptr, pk_ptr, C.size_t(len(pkBytes)), ret_ptr)
	return retBuf, formatErr(code)
}

func AggregatePKsUnchecked(pks ...[]byte) ([]byte, error) {
	pkBytes := make([]byte, 0)
	for _, pk := range pks {
		if C.int(len(pk)) != C.PK_RAW_SIZE {
			return nil, errors.New("invalid bytes provided")
		}
		pkBytes = append(pkBytes, pk...)
	}

	pk_ptr := toPtr(pkBytes)
	retBuf := make([]byte, C.PK_SIZE)
	ret_ptr := toPtr(retBuf)
	C.aggregate_pks_unchecked(pk_ptr, C.size_t(len(pkBytes)), ret_ptr)
	return retBuf, nil
}

func AggregateSig(sig []byte, sigs ...[]byte) ([]byte, error) {
	sig_ptr := toPtr(sig)
	sigBytes := make([]byte, 0)
	for _, sig := range sigs {
		sigBytes = append(sigBytes, sig...)
	}

	sigs_ptr := toPtr(sigBytes)
	retBuf := make([]byte, C.SIG_SIZE)
	ret_ptr := toPtr(retBuf)
	code := C.aggregate_sig(sig_ptr, sigs_ptr, C.size_t(len(sigBytes)), ret_ptr)
	return retBuf, formatErr(code)
}

func PkToRaw(pk []byte) ([]byte, error) {
	pk_ptr := toPtr(pk)
	pkRawBuf := make([]byte, C.PK_RAW_SIZE)
	pkRaw_ptr := toPtr(pkRawBuf)
	code := C.pk_to_raw(pk_ptr, pkRaw_ptr)
	return pkRawBuf, formatErr(code)
}

func toPtr(data []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&data[0]))
}

func formatErr(errCode C.bls_sign_status) error {
	switch errCode {
	case C.BLS_OK:
		return nil
	case C.BLS_INVALID_BYTES:
		return errors.New("invalid bytes provided")
	case C.BLS_VERIFICATION_FAILED:
		return errors.New("verification failed")
	default:
		return errors.New("encountered unknown exit code")
	}
}
