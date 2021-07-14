package blst

import (
	"fmt"
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"testing"
)

// The following tutorial was used to base this benchmarking suite:
// https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
// https://pkg.go.dev/testing
// https://splice.com/blog/lesser-known-features-go-test/

// The -benchtime flag can be used to increase the total number of times the critical piece of code is run. An example
// command for running benchmark is: go test -v -run=Bench -bench=. -benchtime=20s -cpu=1,2,4. This will ensure the
// minimum limit of execution is 20s. Increase the benchtime flag to get more statisticall significant results.

var preventCompilerOptimisationVerifyResult bool

func genNMsgSignaturesFromMPks(b *testing.B, numOfMsgs, numOfSigners int) ([]bls.BLSSecretKey, []bls.BLSPublicKey, []bls.BLSSignature, [][32]byte) {
	var sigs []bls.BLSSignature
	var privK []bls.BLSSecretKey
	var pubK []bls.BLSPublicKey
	var msgs [][32]byte

	sks, pks, err := GenerateValidators(numOfSigners)

	for i := 0; i < numOfMsgs; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}

		msgB := msg.hash()
		signerPrivK, signerPubK := sks[i%numOfSigners], pks[i%numOfSigners]

		sigs = append(sigs, signerPrivK.Sign(msgB.Bytes()))
		privK = append(privK, signerPrivK)
		pubK = append(pubK, signerPubK)
		msgs = append(msgs, msgB)
	}

	return privK, pubK, sigs, msgs
}

func benchmarkAggregateNSignatureFromMPKsAndVerify(b *testing.B, numOfMsgs, numOfSigners int) {
	var verifyR bool
	_, pks, sigs, msgs := genNMsgSignaturesFromMPks(b, numOfMsgs, numOfSigners)
	aggSig := AggregateSignatures(sigs)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		verifyR = aggSig.AggregateVerify(pks, msgs)
		if !verifyR {
			b.Fatal(verifyR)
		}
	}
	preventCompilerOptimisationVerifyResult = verifyR
}

func BenchmarkAggregateNSignatureFromMPKsAndVerify(b *testing.B) {
	bms := []struct {
		numOfMsgs    int
		numOfSigners int
	}{
		{1000, 10},
		{1000, 100},
		{1000, 1000},
		{10000, 10},
		{10000, 100},
		{10000, 1000},
		{10000, 10000},
		{100000, 10},
		{100000, 100},
		{100000, 1000},
		{100000, 10000},
		{100000, 100000},
		{10, 1000},
		{100, 1000},
		{10, 10000},
		{100, 10000},
		{1000, 10000},
		{10, 100000},
		{100, 100000},
		{1000, 100000},
		{10000, 100000},
	}
	for _, bm := range bms {
		b.Run(fmt.Sprintf("%v messages signed by %v private keys", bm.numOfMsgs, bm.numOfSigners), func(b *testing.B) {
			benchmarkAggregateNSignatureFromMPKsAndVerify(b, bm.numOfMsgs, bm.numOfSigners)
		})
	}
}
