package blst

import (
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"testing"
)

// The following tutorial was used to base this benchmarking suite:
// https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
var preventCompilerOptimisationAggSig bls.BLSSignature
var preventCompilerOptimisationVerifyResult bool

func genNMsgSignaturesFromNPks(b *testing.B, n int) ([]bls.BLSSecretKey, []bls.BLSPublicKey, []bls.BLSSignature, [][32]byte) {
	var sigs []bls.BLSSignature
	var msgs [][32]byte
	sks, pks, err := GenerateValidators(n)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		msgB := msg.hash()
		sigs = append(sigs, sks[i].Sign(msgB.Bytes()))
		msgs = append(msgs, msgB)
	}
	return sks, pks, sigs, msgs
}

func benchmarkNAggregateSignatureFromNPKs(b *testing.B, n int) {
	var aggSig bls.BLSSignature
	_, _, sigs, _ := genNMsgSignaturesFromNPks(b, n)
	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}

func benchmarkNAggregateSignatureVerifyFromNPKs(b *testing.B, n int) {
	var verifyR bool
	_, pks, sigs, msgs := genNMsgSignaturesFromNPks(b, n)
	aggSig := AggregateSignatures(sigs)

	for n := 0; n < b.N; n++ {
		verifyR = aggSig.AggregateVerify(pks, msgs)
		if !verifyR {
			b.Fatal(verifyR)
		}
	}
	preventCompilerOptimisationVerifyResult = verifyR
}

// The final benchmark is only run once and that is not statically insignificant, however, the -benchtime flag can be
// used to increase the total number of times the critical piece of code is run. An example command for running
// benchmark is: go test -v -run=Bench -bench=. -benchtime=20s. This will ensure the minimum limit of execution is 20s.
// Increase the benchtime flag to get more statisticall significant results.
func Benchmark1AggregateSignatureFrom1PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromNPKs(b, 1)
}
func Benchmark100DifferentAggregateSignatureFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromNPKs(b, 100)
}
func Benchmark1000DifferentAggregateSignatureFrom1000PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromNPKs(b, 1000)
}
func Benchmark10000DifferentAggregateSignatureFrom10000PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromNPKs(b, 10000)
}

func Benchmark1AggregateSignatureSignatureFrom1PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromNPKs(b, 1)
}
func Benchmark100DifferentAggregateSignatureSignatureFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromNPKs(b, 100)
}
func Benchmark1000DifferentAggregateSignatureSignatureFrom1000PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromNPKs(b, 1000)
}
func Benchmark10000DifferentAggregateSignatureSignatureFrom10000PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromNPKs(b, 10000)
}
