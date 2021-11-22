// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

package bls

// Bls12381Sign provides an interface for BLS123-81 Signing
// and an abstraction over varying implementations (cgo, grpc)
type Bls12381Sign interface {
	GenerateKeys() (secret []byte, public []byte)
	Sign(sk, pk, msg []byte) (signature []byte, err error)
	Verify(apk, sig, msg []byte) (err error)
	CreateApk(pk []byte) (apk []byte, err error)
	AggregatePk(apk []byte, pks ...[]byte)
	AggregateSig(sig []byte, sigs ...[]byte)
}
