package blst

import (
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"testing"
)

var preventCompilerOptimisationAggSig bls.BLSSignature

func Benchmark1AggregateSignatureFrom1PK(b *testing.B) {
	n := 1
	var sigs []bls.BLSSignature
	sk, _, err := GenerateValidators(n)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		sigs = append(sigs, sk[i].Sign(msg.hash().Bytes()))
	}

	var aggSig bls.BLSSignature

	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}

func Benchmark100AggregateSignatureFrom1PK(b *testing.B) {
	n := 100
	var sigs []bls.BLSSignature
	sk, _, err := GenerateValidators(n)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		sigs = append(sigs, sk[i].Sign(msg.hash().Bytes()))
	}

	var aggSig bls.BLSSignature

	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}

func Benchmark1000AggregateSignatureFrom1PK(b *testing.B) {
	n := 1000
	var sigs []bls.BLSSignature
	sk, _, err := GenerateValidators(n)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		sigs = append(sigs, sk[i].Sign(msg.hash().Bytes()))
	}

	var aggSig bls.BLSSignature

	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}

func Benchmark10000AggregateSignatureFrom1PK(b *testing.B) {
	n := 10000
	var sigs []bls.BLSSignature
	sk, _, err := GenerateValidators(n)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		sigs = append(sigs, sk[i].Sign(msg.hash().Bytes()))
	}

	var aggSig bls.BLSSignature

	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}
