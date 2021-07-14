package blst

import (
	"fmt"
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"math/rand"
	"sync"
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

type horizontalAggregate struct {
	pub  []bls.BLSPublicKey
	msgs [][32]byte
	agg  bls.BLSSignature
}

func genNMsgSigsFromMPks(numOfMsgs, numOfSigners int) ([]bls.BLSSecretKey, []bls.BLSPublicKey, []bls.BLSSignature, [][32]byte, error) {
	var sigs []bls.BLSSignature
	var privK []bls.BLSSecretKey
	var pubK []bls.BLSPublicKey
	var msgs [][32]byte

	sks, pks, err := GenerateValidators(numOfSigners)

	for i := 0; i < numOfMsgs; i++ {
		msg := Msg{H: rand.Uint64(), R: rand.Uint64(), S: uint8(rand.Intn(3))}
		if err != nil {
			return nil, nil, nil, nil, err
		}

		msgB := msg.hash()
		signerPrivK, signerPubK := sks[i%numOfSigners], pks[i%numOfSigners]

		sigs = append(sigs, signerPrivK.Sign(msgB.Bytes()))
		privK = append(privK, signerPrivK)
		pubK = append(pubK, signerPubK)
		msgs = append(msgs, msgB)
	}

	return privK, pubK, sigs, msgs, nil
}

func genHorizontalAggregate(numOfMsgsPerSigner, numOfSigners int) ([]horizontalAggregate, error) {
	const aggregationSigners = 1
	var horizontalAggs []horizontalAggregate

	for i := 0; i < numOfSigners; i++ {
		_, pk, sigs, msgs, err := genNMsgSigsFromMPks(numOfMsgsPerSigner, aggregationSigners)
		if err != nil {
			return nil, err
		}
		horizontalAggs = append(horizontalAggs, horizontalAggregate{
			pk,
			msgs,
			AggregateSignatures(sigs),
		})
	}
	return horizontalAggs, nil
}

func aggregateNSigsFromMPKsAndVerify(b *testing.B, numOfMsgs, numOfSigners int) {
	var verifyR bool
	_, pks, sigs, msgs, err := genNMsgSigsFromMPks(numOfMsgs, numOfSigners)
	if err != nil {
		b.Fatal(err.Error())
	}
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

func BenchmarkAggregateNSigsFromMPKsAndVerify(b *testing.B) {
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
			aggregateNSigsFromMPKsAndVerify(b, bm.numOfMsgs, bm.numOfSigners)
		})
	}
}

func horizontalAggregateNFromMPks(b *testing.B, numOfMsgsPerSigner, numOfSigners int, isParallel bool) {
	var verifyR bool
	hAggs, err := genHorizontalAggregate(numOfMsgsPerSigner, numOfSigners)
	if err != nil {
		b.Fatal(err.Error())
	}

	if isParallel {
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			var wg sync.WaitGroup
			var errorCh = make(chan bool, len(hAggs))
			for _, a := range hAggs {
				a := a
				wg.Add(1)
				go func(agg horizontalAggregate) {
					defer wg.Done()
					verifyR = a.agg.AggregateVerify(a.pub, a.msgs)
					if !verifyR {
						errorCh <- verifyR
					}

				}(a)
			}
			wg.Wait()
			close(errorCh)
			for i := range errorCh {
				if !i {
					b.Fatal(i)
				}
			}
		}
	} else {
		b.ResetTimer()
		for n := 0; n < b.N; n++ {
			for _, a := range hAggs {
				verifyR = a.agg.AggregateVerify(a.pub, a.msgs)
				if !verifyR {
					b.Fatal(verifyR)
				}
			}
		}
	}

	preventCompilerOptimisationVerifyResult = verifyR
}

func BenchmarkHorizontalAggregateNFromMPks(b *testing.B) {
	bms := []struct {
		numOfMsgsPerSigner int
		numOfSigners       int
		isParallel         bool
	}{
		{10, 10, false},
		{10, 10, true},
		{100, 10, false},
		{100, 10, true},
		{1000, 10, false},
		{1000, 10, true},
		{10000, 10, false},
		{10000, 10, true},
		{10, 30, false},
		{10, 30, true},
		{100, 30, false},
		{100, 30, true},
		{1000, 30, false},
		{1000, 30, true},
		{10000, 30, false},
		{10000, 30, true},
		{10, 50, false},
		{10, 50, true},
		{100, 50, false},
		{100, 50, true},
		{1000, 50, false},
		{1000, 50, true},
		{10000, 50, false},
		{10000, 50, true},
		{10, 100, false},
		{10, 100, true},
		{100, 100, false},
		{100, 100, true},
		{1000, 100, false},
		{1000, 100, true},
		{10000, 100, false},
		{10000, 100, true},
	}
	for _, bm := range bms {
		b.Run(fmt.Sprintf("%v messages' aggregate per signer for a total of %v signer isParallel %v", bm.numOfMsgsPerSigner, bm.numOfSigners, bm.isParallel), func(b *testing.B) {
			horizontalAggregateNFromMPks(b, bm.numOfMsgsPerSigner, bm.numOfSigners, bm.isParallel)
		})
	}
}
