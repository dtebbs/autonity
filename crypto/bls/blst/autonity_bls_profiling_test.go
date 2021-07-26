package blst

import (
	"fmt"
	"github.com/clearmatics/autonity/common"
	"github.com/clearmatics/autonity/core/types"
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"github.com/clearmatics/autonity/rlp"
	"io"
	"sync"
	"testing"
	"time"
)

type Msg struct {
	H uint64
	R uint64
	S uint8
}

func (m *Msg) hash() common.Hash {
	b, err := rlp.EncodeToBytes(&Msg{
		H: m.H,
		R: m.R,
		S: m.S,
	})
	if err != nil {
		panic(err)
	}
	return types.RLPHash(b)
}

// EncodeRLP serializes m into the Ethereum RLP format.
func (m *Msg) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, []interface{}{m.H, m.R, m.S})
}

// generate a set of validators.
func GenerateValidators(n int) ([]bls.BLSSecretKey, []bls.BLSPublicKey, error) {
	sk := make([]bls.BLSSecretKey, n)
	pk := make([]bls.BLSPublicKey, n)
	for i := 0; i < n; i++ {
		s, err := RandKey()
		if err != nil {
			return nil, nil, err
		}
		sk[i] = s
		pk[i] = s.PublicKey()
	}
	return sk, pk, nil
}

// the information of a voting step to recreate the msgs on verification phase.
type AbsentParticipants struct {
	Msg
	AbsentValidators []int // the index of validators from which that the msg is not received after the delay of delta.
}

/*
 Vertical aggregation, aggregate those signatures of the same msg signed by different validators.
*/
type EProofVerticalAgg struct {
	MinRoundsPerHeight []uint64 // min round number of each height from 1st height to the last height of the Epoch.
	// Todo: for actual signatures we would need to make sure that they are ordered otherwise the verification can fail
	AggregatedSignatures []bls.BLSSignature   // the aggregated msg signature of per voting steps, sorted by height, round and steps.
	Absences             []AbsentParticipants // the set of validators that are not participated on a specific voting step.
}

func NewVerticalAggEProof(v []bls.BLSSecretKey, epochLength int, avgRound uint64) *EProofVerticalAgg {
	endHeight := uint64(epochLength)
	eProof := EProofVerticalAgg{}
	for h := uint64(0); h < endHeight; h++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
		for r := uint64(0); r < avgRound; r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				sigs := make([]bls.BLSSignature, 0, len(v))
				for i := 0; i < len(v); i++ {
					sig := v[i].Sign(m.hash().Bytes())
					sigs = append(sigs, sig)
				}
				aggSig := AggregateSignatures(sigs)
				eProof.AggregatedSignatures = append(eProof.AggregatedSignatures, aggSig)
			}
		}
	}
	return &eProof
}

// we assume there are no omission faults, let's experience the performance over signature verification
func (vt *EProofVerticalAgg) ValidateEProof(startHeight uint64, pubKeys []bls.BLSPublicKey) time.Duration {
	var wg sync.WaitGroup
	var errorCh = make(chan bool, len(vt.AggregatedSignatures))
	mx := sync.RWMutex{}
	epochLength := len(vt.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	aggIndex := 0
	beforeTest := time.Now()
	for h := startHeight; h < endHeight; h++ {
		minRound := vt.MinRoundsPerHeight[h-startHeight]
		for r := uint64(0); r < uint64(minRound); r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}

				aggI := aggIndex
				wg.Add(1)

				go func(h common.Hash, i int) {
					defer wg.Done()

					mx.RLock()
					ok := vt.AggregatedSignatures[i].FastAggregateVerify(pubKeys, h)
					mx.RUnlock()
					if !ok {
						errorCh <- false
					}

				}(m.hash(), aggI)
				aggIndex++
			}
		}
	}

	wg.Wait()
	afterTest := time.Now()
	close(errorCh)
	for i := range errorCh {
		panic(i)
	}
	return afterTest.Sub(beforeTest)
}

/*
 Horizontal aggregation, aggregate those signatures of different messages signed by same validator through out the
 entire epoch.
*/
type EProofHorizontalAgg struct {
	MinRoundsPerHeight      []uint64                 // min round number of each height from 1st height to the last height of the Epoch.
	CommitteeActivityProofs []ValidatorActivityProof // each for per validator.
}

// the activity proof of a specific validator.
type ValidatorActivityProof struct {
	ValidatorIndex int              // the validator index.
	AggSignature   bls.BLSSignature // the aggregated msg signature of the entire epoch of this validator, sorted by
	// pattern: height, round, step
	MissedMsgs []Msg // missing msgs of this validator, sorted by height, round and step.
}

// generate a full view of the entire proof of activities, let's assume there are no omission.
func NewHorizontalAggEProof(v []bls.BLSSecretKey, epochLength int, avgRound uint64) *EProofHorizontalAgg {
	eProof := EProofHorizontalAgg{}
	// set the minimum round to avg minimum round: 2, for each height
	for i := 0; i < epochLength; i++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
	}

	// assume there are no omission, so we aggregate all the msg sent by each validator.
	for i := 0; i < len(v); i++ {
		sigs := make([]bls.BLSSignature, 0, epochLength*int(avgRound)*2)
		for h := uint64(0); h < uint64(epochLength); h++ {
			for r := uint64(0); r < avgRound; r++ {
				for s := uint8(0); s < 2; s++ {
					m := Msg{
						H: h,
						R: r,
						S: s,
					}
					sig := v[i].Sign(m.hash().Bytes())
					sigs = append(sigs, sig)
				}
			}
		}
		validatorP := ValidatorActivityProof{
			ValidatorIndex: i,
			AggSignature:   AggregateSignatures(sigs),
			MissedMsgs:     nil,
		}
		eProof.CommitteeActivityProofs = append(eProof.CommitteeActivityProofs, validatorP)
	}

	return &eProof
}

func (hp *EProofHorizontalAgg) ValidateEProof(startHeight uint64, pubKeys []bls.BLSPublicKey) time.Duration {
	var wg sync.WaitGroup
	var errorCh = make(chan bool, len(hp.CommitteeActivityProofs))

	epochLength := len(hp.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	beforeTest := time.Now()

	for i := 0; i < len(hp.CommitteeActivityProofs); i++ {
		pKey := pubKeys[hp.CommitteeActivityProofs[i].ValidatorIndex]
		aggSig := hp.CommitteeActivityProofs[i].AggSignature
		// there is no missing msg, then to re-create all the msgs.
		keys := make([]bls.BLSPublicKey, 0, epochLength*2*2)
		msgs := make([][32]byte, 0, epochLength*2*2)
		for h := startHeight; h < endHeight; h++ {
			minRound := hp.MinRoundsPerHeight[h-startHeight]
			for r := uint64(0); r < minRound; r++ {
				for s := uint8(0); s < uint8(2); s++ {
					m := Msg{
						H: h,
						R: r,
						S: s,
					}
					keys = append(keys, pKey)
					msgs = append(msgs, m.hash())
				}
			}
		}

		wg.Add(1)
		go func(ks []bls.BLSPublicKey, ms [][32]byte) {
			defer wg.Done()
			ok := aggSig.AggregateVerify(ks, ms)
			if !ok {
				errorCh <- false
			}

		}(keys, msgs)
	}

	wg.Wait()
	afterTest := time.Now()
	close(errorCh)
	for i := range errorCh {
		panic(i)
	}
	return afterTest.Sub(beforeTest)
}

/*
  Hybrid aggregation, aggregate those signatures of the same message signed by different validator, then to horizontally
  aggregate the signatures generated by last step into single signature for the entire epoch, such that we gain with
  less storage cost, and the verification performance is also optimized.
*/
type EProofHybrid struct {
	MinRoundsPerHeight  []uint64 // min round number of each height from 1st height to the last height of the Epoch.
	AggregatedSignature bls.BLSSignature
	Absences            []AbsentParticipants //to recreate the msgs and to recreate the aggregated public keys.
}

func NewHybridAggEProof(v []bls.BLSSecretKey, epochLength int, avgRound uint64) *EProofHybrid {
	endHeight := uint64(epochLength)
	eProof := EProofHybrid{}
	verticalAggSignatures := make([]bls.BLSSignature, 0, epochLength*int(avgRound)*2)
	for h := uint64(0); h < endHeight; h++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
		for r := uint64(0); r < avgRound; r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				sigs := make([]bls.BLSSignature, 0, len(v))
				for i := 0; i < len(v); i++ {
					sig := v[i].Sign(m.hash().Bytes())
					sigs = append(sigs, sig)
				}
				aggSig := AggregateSignatures(sigs)
				verticalAggSignatures = append(verticalAggSignatures, aggSig)
			}
		}
	}
	eProof.AggregatedSignature = AggregateSignatures(verticalAggSignatures)
	return &eProof
}

// we assume there are no omission faults, let's experience the performance over signature verification
func (hb *EProofHybrid) ValidateEProof(startHeight uint64, pubKeys []bls.BLSPublicKey) time.Duration {
	beforeTest := time.Now()
	epochLength := len(hb.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	// assume there are no omission faults, so we recreate all the msgs and aggregated public keys.
	aggPublicKeys := make([]bls.BLSPublicKey, 0, epochLength*2*2)
	msgs := make([][32]byte, 0, epochLength*2*2)
	for h := startHeight; h < endHeight; h++ {
		minRound := hb.MinRoundsPerHeight[h-startHeight]
		for r := uint64(0); r < uint64(minRound); r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				aggPublicKeys = append(aggPublicKeys, AggregatePublicKeysV2(pubKeys))
				msgs = append(msgs, m.hash())
			}
		}
	}
	ok := hb.AggregatedSignature.AggregateVerify(aggPublicKeys, msgs)
	if !ok {
		panic(ok)
	}
	afterTest := time.Now()
	return afterTest.Sub(beforeTest)
}

// this test compares the vertical, horizontal and hybrid signature aggregations performance.
func TestSignatureAggregationComparing(t *testing.T) {
	tests := []struct {
		name          string
		committeeSize int
		lengthOfEPoch int
		averageRound  int
	}{
		{
			"10 validators, 30 blocks epoch, average min round 2",
			10,
			30,
			2,
		},
		{
			"10 validators, 60 blocks epoch, average min round 2",
			10,
			60,
			2,
		},
		{
			"10 validators, 90 blocks epoch, average min round 2",
			10,
			90,
			2,
		},
		{
			"10 validators, 120 blocks epoch, average min round 2",
			10,
			120,
			2,
		},
		{
			"15 validators, 30 blocks epoch, average min round 2",
			15,
			30,
			2,
		},
		{
			"15 validators, 60 blocks epoch, average min round 2",
			15,
			60,
			2,
		},
		{
			"15 validators, 90 blocks epoch, average min round 2",
			15,
			90,
			2,
		},
		{
			"15 validators, 120 blocks epoch, average min round 2",
			15,
			120,
			2,
		},
		{
			"21 validators, 30 blocks epoch, average min round 2",
			21,
			30,
			2,
		},
		{
			"21 validators, 60 blocks epoch, average min round 2",
			21,
			60,
			2,
		},
		{
			"21 validators, 90 blocks epoch, average min round 2",
			21,
			90,
			2,
		},
		{
			"21 validators, 120 blocks epoch, average min round 2",
			21,
			120,
			2,
		},
	}

	times := 100
	fmt.Println()
	for _, test := range tests {
		fmt.Println()
		fmt.Println("TestCase: ", test.name, ", total msgs: ", test.lengthOfEPoch*test.averageRound*2, "*", test.committeeSize)
		run(test.committeeSize, test.lengthOfEPoch, test.averageRound, times)
		fmt.Println()
	}
}

func run(committeeSize int, epochLength int, avgRound int, times int) {
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	if err != nil {
		panic(err)
	}

	// test vertical aggregation.
	d := time.Duration(0)
	eProofVertical := NewVerticalAggEProof(secretKeys, epochLength, uint64(avgRound))
	for i := 0; i < times; i++ {
		d += eProofVertical.ValidateEProof(uint64(0), pubKeys)
	}
	fmt.Println("VerticalAGG AVG time: \t\t", d.Seconds()/float64(times), "seconds to verify", committeeSize, "sets of aggregated messages with each set of", epochLength*avgRound*2, "messages")

	// test horizontal aggregation.
	d = time.Duration(0)
	eProofHorizontal := NewHorizontalAggEProof(secretKeys, epochLength, uint64(avgRound))
	for i := 0; i < times; i++ {
		d += eProofHorizontal.ValidateEProof(uint64(0), pubKeys)
	}
	fmt.Println("HorizontalAGG AVG time: \t", d.Seconds()/float64(times), "seconds to verify", committeeSize, "sets of aggregated messages with each set of", epochLength*avgRound*2, "messages")

	// test hybrid aggregation.
	d = time.Duration(0)
	eProofHybrid := NewHybridAggEProof(secretKeys, epochLength, uint64(avgRound))
	for i := 0; i < times; i++ {
		d += eProofHybrid.ValidateEProof(uint64(0), pubKeys)
	}
	fmt.Println("HybridAGG AVG time: \t\t", d.Seconds()/float64(times), "seconds to verify", committeeSize, "sets of aggregated messages with each set of", epochLength*avgRound*2, "messages")
}
