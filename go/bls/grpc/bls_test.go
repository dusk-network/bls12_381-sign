// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

package bls

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConnectDisconnect(t *testing.T) {
	Connect()
}

func TestGenerateKeysIPC(t *testing.T) {

	sk, pk := GenerateKeys()
	if sk == nil || pk == nil {
		t.Fatal("generate keys failed")
	}
	assert.NotEqual(t, sk, make([]byte, 32))
	assert.NotEqual(t, pk, make([]byte, 96))
}

func TestSignVerifyIPC(t *testing.T) {

	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)
	sig, err := Sign(sk, pk, msg)
	if err != nil {
		t.Fatal(err)
	}

	apk, err := CreateApk(pk)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(apk, sig, msg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyWrongKeyIPC(t *testing.T) {

	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)
	sig, err := Sign(sk, pk, msg)
	if err != nil {
		t.Fatal(err)
	}

	_, pk = GenerateKeys()

	apk, err := CreateApk(pk)
	if err != nil {
		t.Fatal(err)
	}

	assert.Error(t, Verify(apk, sig, msg))
}

func TestAggregationIPC(t *testing.T) {

	// Generate keys
	sk1, pk1 := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)
	sig1, err := Sign(sk1, pk1, msg)
	if err != nil {
		t.Fatal(err)
	}

	apk1, err := CreateApk(pk1)
	if err != nil {
		t.Fatal(err)
	}

	// Aggregating pk
	sk2, pk2 := GenerateKeys()
	sk3, pk3 := GenerateKeys()
	apk2, err := AggregatePk(apk1, pk2, pk3)
	if err != nil {
		t.Fatal(err)
	}

	// Aggregating sigs
	sig2, err := Sign(sk2, pk2, msg)
	if err != nil {
		t.Fatal(err)
	}

	sig3, err := Sign(sk3, pk3, msg)
	if err != nil {
		t.Fatal(err)
	}

	aggSig, err := AggregateSig(sig1, sig2, sig3)
	if err != nil {
		t.Fatal(err)
	}

	// Aggregated verification
	err = Verify(apk2, aggSig, msg)
	if err != nil {
		t.Fatal(err)
	}
}

func mustDecode(str string) []byte {
	ret, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return ret
}

func TestAggregationSxS(t *testing.T) {
	sk1 := mustDecode("275825c0c399fe8aa175dfb048632982ac8c67f9a1e1b99c85da7773d135eb20")
	pk1 := mustDecode("abd2734535d9d46c150b716ed7b61e269e2fe50d34cc1a3ba4d3b88b2a56b70df7452d049c2b836da7030e809ceb2aab0b7580f7a07d25b27e52ca50a4b47d77e5b803a4cd6693947081623f03b5085c4738019529db74caab836af2e6bd7899")
	msg := mustDecode("3ca997e58872f360c0435bf095631be4744455101c180c6f54534523db2ab9a228ce4923736905eb3570559011af2c6016856b3c264679e5efc0157ab08eb0aed14f383951bca11a3d55ce045522a5ebbcf7f31ca42bce27bbe21051571cfef20e275ff4")
	sig1 := mustDecode("953a0f89281757bb446d876014a764d9f544fd0f79c1db8000db9bdcabc6edac33c88645f11ad1bea2b7c24e04720d32")
	apk1 := mustDecode("a168e9f5081143d32e03ac573f24a1b4d64ca34c9cc447d6fe9c25e2aa72faa08b8acdbedcc3a3bddf391ae6c23e689214377c136f4f367d0096bf1786ce43b94742a2f126fd89f70012604d37dda3f6b1c51fec01f9236eeb733a5b5ecf70da")
	sk2 := mustDecode("aeae057edbe5f444a060f6f91ed2a1ca3408bebb337b695f2819c90c62283917")
	pk2 := mustDecode("afb3ab8b5a4a86875921f9779ce82026b90ec0d60def8819f5f99e6e1cf3960d33ec8999f347bdef1fd356c30a585e73067f47f9ee371d45ff3f92b7df21df1b79ec5e58dd4b7b781d06a83b97ed5d3034c88de68461fad5d8f6f4107f7d8e9f")
	sk3 := mustDecode("5f618fef73a63402929892ad6242cafc9d5e2c7ecef02aa90646887b9a9bd335")
	pk3 := mustDecode("89337f90d1aaff5f4884e068435596d0d157b424c0f6eb88554f1f922edcd69ca8e92408942609441b4b4b31a0ff7a331810e6cc835ee8a483f9d8d93347f2559e5db04a0aaeff8a175013652cb7f772e14e68f7c49c89f202ac0988c296a0bb")
	apk2 := mustDecode("a02a321e057da18d6119fdfb078b14a60ad61364450fd55493502320ffda62d66549dd214a7045e1c36be76425c23352007ad5d48330a7429753297540810a5f8ddf11f40c14de8dd2b807e7ff5276e1899981b70bc4ecb0ae355de5eaeff40b")
	sig2 := mustDecode("968c3110687dbf576a868168d783edaa97188ceff3f7b2bcbe354d5dbdba0d369e68fc24f3d3adf574500cd5a7b7235b")
	sig3 := mustDecode("869bea0b9cb94f30a0b71b50bafcb4fb985f5dbff8e4f783ebfc7228f82a12fb507c8e0ccb0b5230ddddcd6d70ff3f21")
	aggSig := mustDecode("9607f61411bbc73fcdf0869ac7449b72020b59a4eee41edb7f5820213fcd8cf2d44375839f3ded7de7e9b741600acbeb")


	sig1a, err := Sign(sk1, pk1, msg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(sig1), hex.EncodeToString(sig1a))

	apk1a, err := CreateApk(pk1)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(apk1), hex.EncodeToString(apk1a))

	// Aggregating pk
	apk2a, err := AggregatePk(apk1, pk2, pk3)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(apk2), hex.EncodeToString(apk2a))

	// Aggregating sigs
	sig2a, err := Sign(sk2, pk2, msg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(sig2), hex.EncodeToString(sig2a))

	sig3a, err := Sign(sk3, pk3, msg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(sig3), hex.EncodeToString(sig3a))

	aggSiga, err := AggregateSig(sig1, sig2, sig3)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, hex.EncodeToString(aggSig), hex.EncodeToString(aggSiga))

	// Aggregated verification
	err = Verify(apk2, aggSig, msg)
	if err != nil {
		t.Fatal(err)
	}
}
