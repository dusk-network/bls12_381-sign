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

func TestConnect(t *testing.T) {
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
	sig1 := mustDecode("8a8c630f0ef76ef839e5efc381c8c4e174a4df519c3ece7700cf4fc3605e8b28eb4939aae29a0d6a7d886f09951e8524")
	apk1 := mustDecode("a30093bf196c836c7bab41bdc31157654d9e62688093bb38263a9c87b91f04adecfb0d8cce54b05acdf13a7d1812a83d0888322868d58fc3536bf03e3e36929d3811ee0219d80760307ce1cf6abe6f069b246a6b00390693368824c4d807a470")
	sk2 := mustDecode("aeae057edbe5f444a060f6f91ed2a1ca3408bebb337b695f2819c90c62283917")
	pk2 := mustDecode("afb3ab8b5a4a86875921f9779ce82026b90ec0d60def8819f5f99e6e1cf3960d33ec8999f347bdef1fd356c30a585e73067f47f9ee371d45ff3f92b7df21df1b79ec5e58dd4b7b781d06a83b97ed5d3034c88de68461fad5d8f6f4107f7d8e9f")
	sk3 := mustDecode("5f618fef73a63402929892ad6242cafc9d5e2c7ecef02aa90646887b9a9bd335")
	pk3 := mustDecode("89337f90d1aaff5f4884e068435596d0d157b424c0f6eb88554f1f922edcd69ca8e92408942609441b4b4b31a0ff7a331810e6cc835ee8a483f9d8d93347f2559e5db04a0aaeff8a175013652cb7f772e14e68f7c49c89f202ac0988c296a0bb")
	apk2 := mustDecode("8abacd1d201478f19898cc31c7fb7dc3c631698e497c641c6cfe1628f55f6b592cedc6903a009cdc080f13e732763b65123c854563e20894c31c538543e452e47057a3c66ca85b6a58ea8518c9ac56fe3b8489cbded4610d5a2763cc9a0dfb35")
	sig2 := mustDecode("913e34c462f1d171a08df75da1fdcbb6a6f6268be14fd304014459feb7201254bc43ddbb2456acb2f454ae4f8b603fa7")
	sig3 := mustDecode("b6b42e47d92f011afb4f63266a4a40af458c2d050d6ccb4320e498a37d0d11565e67783c9f0202f864db591c70f8f4f4")
	aggSig := mustDecode("b36d9f47b3b0dc9c370d034c9ab56adcd826bda37744c5f24f1b874c50f740dcb161d0d4a32eb36ee7b2f7ac94982300")


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

func TestDisconnect(t *testing.T) {
	Disconnect()
}
