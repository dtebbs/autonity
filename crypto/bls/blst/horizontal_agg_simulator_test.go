package blst

import (
	"fmt"
	"github.com/clearmatics/autonity/crypto/bls/common"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

/*
  Horizontal Aggregation:
  That all the msg sent by Pi are aggregated into a single signature.
  Msgs: (m1, m2, ...... mX), the signature of each msg is aggregated into 1 single signature throughout the epoch.
  AggSignatures: (AggSignature_Node0, AggSignature_Node1, ......)

  Pro: less storage cost.
  con: high computing cost.
*/

// the overview of the activities for the entire epoch, it will be submit by Pi.
type EpochActivityProofV2 struct {
	MinRoundsPerHeight      []uint64                 // min round number of each height from 1st height to the last height of the Epoch.
	CommitteeActivityProofs []ValidatorActivityProof // each for per validator.
}

// the activity proof of a specific validator.
type ValidatorActivityProof struct {
	ValidatorIndex int                 // the validator index.
	AggSignature   common.BLSSignature // the aggregated msg signature of the entire epoch of this validator, sorted by
	// pattern: height, round, step
	MissedMsgs []Msg // missing msgs of this validator, sorted by height, round and step.
}

// generate a full view of the entire proof of activities, let's assume there are no omission.
func GenerateEpochActivityProofV2(v []common.BLSSecretKey, epochLength int, avgRound uint64) EpochActivityProofV2 {
	eProof := EpochActivityProofV2{}
	// set the minimum round to avg minimum round: 2, for each height
	for i := 0; i < epochLength; i++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
	}

	// assume there are no omission, so we aggregate all the msg sent by each validator.
	for i := 0; i < len(v); i++ {
		sigs := make([]common.BLSSignature, 0, epochLength*int(avgRound)*2)
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

	return eProof
}

func ValidateEpochActivityProofV2(p EpochActivityProofV2, startHeight uint64, pubKeys []common.BLSPublicKey) (time.Duration, bool) {
	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	beforeTest := time.Now()
	for i := 0; i < len(p.CommitteeActivityProofs); i++ {
		pKey := pubKeys[p.CommitteeActivityProofs[i].ValidatorIndex]
		aggSig := p.CommitteeActivityProofs[i].AggSignature
		// there is no missing msg, then to re-create all the msgs.
		keys := make([]common.BLSPublicKey, 0, epochLength*2*2)
		msgs := make([][32]byte, 0, epochLength*2*2)
		for h := startHeight; h < endHeight; h++ {
			minRound := p.MinRoundsPerHeight[h-startHeight]
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
		ok := aggSig.AggregateVerify(keys, msgs)
		if !ok {
			return 0, false
		}
	}
	afterTest := time.Now()
	//fmt.Println(afterTest.Sub(beforeTest).Seconds())
	return afterTest.Sub(beforeTest), true
}

func ValidateEpochActivityProofV2WaitGroup(p EpochActivityProofV2, startHeight uint64, pubKeys []common.BLSPublicKey) bool {
	var wg sync.WaitGroup
	var errorCh = make(chan bool, len(p.CommitteeActivityProofs))

	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	beforeTest := time.Now()

	for i := 0; i < len(p.CommitteeActivityProofs); i++ {
		pKey := pubKeys[p.CommitteeActivityProofs[i].ValidatorIndex]
		aggSig := p.CommitteeActivityProofs[i].AggSignature
		// there is no missing msg, then to re-create all the msgs.
		keys := make([]common.BLSPublicKey, 0, epochLength*2*2)
		msgs := make([][32]byte, 0, epochLength*2*2)
		for h := startHeight; h < endHeight; h++ {
			minRound := p.MinRoundsPerHeight[h-startHeight]
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
		go func(ks []common.BLSPublicKey, ms [][32]byte) {
			defer wg.Done()
			ok := aggSig.AggregateVerify(ks, ms)
			if !ok {
				errorCh <- false
			}

		}(keys, msgs)
	}

	wg.Wait()
	afterTest := time.Now()
	fmt.Println(afterTest.Sub(beforeTest).Seconds())
	close(errorCh)
	for i := range errorCh {
		return i
	}
	return true
}

// return the time cost of the verification of aggregated signatures.
func run(committeeSize int, epochLength int, avgRound int) time.Duration {
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	if err != nil {
		panic(err)
	}

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from Pi.
	eProof := GenerateEpochActivityProofV2(secretKeys, epochLength, uint64(avgRound))

	// validate the proof sent by pi.
	duration, ok := ValidateEpochActivityProofV2(eProof, uint64(0), pubKeys)
	if !ok {
		panic(ok)
	}
	return duration
}

func TestOneAggSignaturePerNodeSimulator(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 20      // 30 seconds.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	require.NoError(t, err)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from Pi.
	eProof := GenerateEpochActivityProofV2(secretKeys, lengthOfEpoch, uint64(averageMinRounds))

	// validate the proof sent by pi.
	_, ok := ValidateEpochActivityProofV2(eProof, uint64(0), pubKeys)
	require.True(t, ok)
}

func TestOneAggSignaturePerNodeSimulatorWaitGroup(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 20      // 30 seconds.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	require.NoError(t, err)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from Pi.
	eProof := GenerateEpochActivityProofV2(secretKeys, lengthOfEpoch, uint64(averageMinRounds))

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofV2WaitGroup(eProof, uint64(0), pubKeys)
	require.True(t, ok)
}

func TestHorizontalAggWithDifferentSettings(t *testing.T) {
	tests := []struct{
		name string
		committeSize int
		lengthOfEPoch int
		averageRound int
	}{
		{
			"horizontal aggregation: \t 10 validators, 30 blocks epoch, average min round 2",
			10,
			30,
			2,
		},
		{
			"horizontal aggregation: \t 10 validators, 60 blocks epoch, average min round 2",
			10,
			60,
			2,
		},
		{
			"horizontal aggregation: \t 10 validators, 90 blocks epoch, average min round 2",
			10,
			90,
			2,
		},
		{
			"horizontal aggregation: \t 15 validators, 30 blocks epoch, average min round 2",
			15,
			30,
			2,
		},
		{
			"horizontal aggregation: \t 15 validators, 60 blocks epoch, average min round 2",
			15,
			60,
			2,
		},
		{
			"horizontal aggregation: \t 15 validators, 90 blocks epoch, average min round 2",
			15,
			90,
			2,
		},
		{
			"horizontal aggregation: \t 21 validators, 30 blocks epoch, average min round 2",
			21,
			30,
			2,
		},
		{
			"horizontal aggregation: \t 21 validators, 60 blocks epoch, average min round 2",
			21,
			60,
			2,
		},
		{
			"horizontal aggregation: \t 21 validators, 90 blocks epoch, average min round 2",
			21,
			90,
			2,
		},
	}

	times := 10
	fmt.Println()
	for _, test := range tests {
		fmt.Println(test.name)
		d := time.Duration(0)
		for i:=0; i<times; i++ {
			d += run(test.committeSize, test.lengthOfEPoch, test.averageRound)
		}
		fmt.Println("average time: \t\t\t\t", d.Seconds()/float64(times), "seconds to verify", test.committeSize, "sets of aggregated messages with each set of", test.lengthOfEPoch*test.averageRound*2, "messages")
		fmt.Println()
	}
}