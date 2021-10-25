package bls

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateKeys(t *testing.T) {
	sk, pk := GenerateKeys()
	if sk == nil || pk == nil {
		t.Fatal("generate keys failed")
	}
	assert.NotEqual(t, sk, make([]byte, 32))
	assert.NotEqual(t, pk, make([]byte, 96))
}

func TestSignVerify(t *testing.T) {
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

func TestVerifyWrongKey(t *testing.T) {
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

func TestAggregation(t *testing.T) {
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

func BenchmarkSign(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(sk, pk, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	sig, err := Sign(sk, pk, msg)
	if err != nil {
		b.Fatal(err)
	}

	apk, err := CreateApk(pk)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(apk, sig, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAggregatePk(b *testing.B) {
	_, pk := GenerateKeys()

	apk, err := CreateApk(pk)
	if err != nil {
		b.Fatal(err)
	}

	pks := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		_, pk := GenerateKeys()
		pks[i] = pk
	}

	b.ResetTimer()
	for i := 0; i < len(pks); i++ {
		AggregatePk(apk, pks[i])
	}
}

func BenchmarkAggregateSig(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	sig, err := Sign(sk, pk, msg)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AggregateSig(sig, sig); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSwitchToIPC(b *testing.B) {
	SwitchToIPC()
}
func BenchmarkSignIPC(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(sk, pk, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyIPC(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	sig, err := Sign(sk, pk, msg)
	if err != nil {
		b.Fatal(err)
	}

	apk, err := CreateApk(pk)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := Verify(apk, sig, msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAggregatePkIPC(b *testing.B) {
	_, pk := GenerateKeys()

	apk, err := CreateApk(pk)
	if err != nil {
		b.Fatal(err)
	}

	pks := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		_, pk := GenerateKeys()
		pks[i] = pk
	}

	b.ResetTimer()
	for i := 0; i < len(pks); i++ {
		AggregatePk(apk, pks[i])
	}
}

func BenchmarkAggregateSigIPC(b *testing.B) {
	sk, pk := GenerateKeys()
	msg := make([]byte, 100)
	rand.Read(msg)

	sig, err := Sign(sk, pk, msg)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AggregateSig(sig, sig); err != nil {
			b.Fatal(err)
		}
	}
}
