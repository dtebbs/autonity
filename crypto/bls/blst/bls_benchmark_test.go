package blst

import (
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"testing"
)

// The following tutorial was used to base this benchmarking suite:
// https://dave.cheney.net/2013/06/30/how-to-write-benchmarks-in-go
// https://pkg.go.dev/testing
// https://splice.com/blog/lesser-known-features-go-test/

var preventCompilerOptimisationAggSig bls.BLSSignature
var preventCompilerOptimisationVerifyResult bool

func genNMsgSignaturesFromMPks(b *testing.B, n, m int) ([]bls.BLSSecretKey, []bls.BLSPublicKey, []bls.BLSSignature, [][32]byte) {
	var sigs []bls.BLSSignature
	var privK []bls.BLSSecretKey
	var pubK []bls.BLSPublicKey
	var msgs [][32]byte
	sks, pks, err := GenerateValidators(m)
	for i := 0; i < n; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			b.Fatal(err.Error())
		}
		msgB := msg.hash()
		signerPrivK, signerPubK := sks[i%m], pks[i%m]
		sigs = append(sigs, signerPrivK.Sign(msgB.Bytes()))
		privK = append(privK, signerPrivK)
		pubK = append(pubK, signerPubK)
		msgs = append(msgs, msgB)
	}
	return privK, pubK, sigs, msgs
}

func benchmarkNAggregateSignatureFromMPKs(b *testing.B, n, m int) {
	var aggSig bls.BLSSignature
	_, _, sigs, _ := genNMsgSignaturesFromMPks(b, n, m)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		aggSig = AggregateSignatures(sigs)
	}
	preventCompilerOptimisationAggSig = aggSig
}

func benchmarkNAggregateSignatureVerifyFromMPKs(b *testing.B, n, m int) {
	var verifyR bool
	_, pks, sigs, msgs := genNMsgSignaturesFromMPks(b, n, m)
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

func benchmarkNAggregateSignatureVerifyFromMPKsParallel(b *testing.B, n, m int) {
	var verifyR bool
	_, pks, sigs, msgs := genNMsgSignaturesFromMPks(b, n, m)
	aggSig := AggregateSignatures(sigs)

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			verifyR = aggSig.AggregateVerify(pks, msgs)
			if !verifyR {
				b.Fatal(verifyR)
			}
		}
	})
	preventCompilerOptimisationVerifyResult = verifyR
}

// The final benchmark is only run once and that is not statically insignificant, however, the -benchtime flag can be
// used to increase the total number of times the critical piece of code is run. An example command for running
// benchmark is: go test -v -run=Bench -bench=. -benchtime=20s -cpu=1,2,4. This will ensure the minimum limit of
// execution is 20s. Increase the benchtime flag to get more statisticall significant results.
func Benchmark1AggregateSignatureFrom1PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromMPKs(b, 1, 1)
}
func Benchmark100DifferentAggregateSignatureFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromMPKs(b, 100, 100)
}
func Benchmark1000DifferentAggregateSignatureFrom1000PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromMPKs(b, 1000, 1000)
}
func Benchmark10000DifferentAggregateSignatureFrom10000PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromMPKs(b, 10000, 1000)
}

func Benchmark1AggregateSignatureSignatureVerifyFrom1PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKs(b, 1, 1)
}
func Benchmark100DifferentAggregateSignatureVerifyFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKs(b, 100, 100)
}
func Benchmark1000DifferentAggregateSignatureVerifyFrom1000PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKs(b, 1000, 1000)
}
func Benchmark10000DifferentAggregateSignatureVerifyFrom10000PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKs(b, 10000, 10000)
}

func Benchmark1000DifferentAggregateSignatureFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureFromMPKs(b, 1000, 100)
}

func Benchmark1000DifferentAggregateSignatureVerifyFrom100PKs(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKs(b, 1000, 100)
}

func Benchmark1000DifferentAggregateSignatureVerifyFrom100PKsParallel(b *testing.B) {
	benchmarkNAggregateSignatureVerifyFromMPKsParallel(b, 1000, 100)
}
