package blst

import (
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"testing"
)

var preventCompilerOptimisationAggSig bls.BLSSignature

func benchmarkNDifferentAggregateSignature(n int, b *testing.B) {
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

// The final benchmark is only run once and that is not statically insignificant, however, the -benchtime flag can be
// used to increase the total number of times the critical piece of code is run. An example command for running
// benchmark is: go test -v -run=Bench -bench=. -benchtime=20s. This will ensure the minimum limit of execution is 20s.
func Benchmark1AggregateSignatureFrom1PK(b *testing.B) {
	benchmarkNDifferentAggregateSignature(1, b)
}
func Benchmark100DifferentAggregateSignatureFrom1PK(b *testing.B) {
	benchmarkNDifferentAggregateSignature(100, b)
}
func Benchmark1000DifferentAggregateSignatureFrom1PK(b *testing.B) {
	benchmarkNDifferentAggregateSignature(1000, b)
}
func Benchmark10000DifferentAggregateSignatureFrom1PK(b *testing.B) {
	benchmarkNDifferentAggregateSignature(10000, b)
}
