package blst

import (
	"fmt"
	"github.com/clearmatics/autonity/common"
	"github.com/herumi/bls-go-binary/bls"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

type EpochActivityProofV1Herumi struct {
	MinRoundsPerHeight []int // min round number of each height from 1st height to the last height of the Epoch.
	// Todo: for actual signatures we would need to make sure that they are ordered otherwise the verification can fail
	AggregatedSignatures []bls.Sign  // the aggregated msg signature of per voting steps, sorted by height, round and steps.
	Absences             []AbsentParticipants // the set of validators that are not participated on a specific voting step.
}

func GenerateValidatorsHerumi(n int) ([]bls.SecretKey, []bls.PublicKey) {
	sk := make([]bls.SecretKey, n)
	pk := make([]bls.PublicKey, n)
	for i := 0; i < n; i++ {
		sk[i].SetByCSPRNG()
		pk[i] = *sk[i].GetPublicKey()
	}
	return sk, pk
}

// generate a full view of the entire proof of activities, let's assume there are no omission.
func GenerateEpochActivityProofHerumi(v []bls.SecretKey, epochLength int, avgRound int) EpochActivityProofV1Herumi {
	endHeight := uint64(epochLength)
	eProof := EpochActivityProofV1Herumi{}
	for h := uint64(0); h < endHeight; h++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
		for r := uint64(0); r < uint64(avgRound); r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				sigs := make([]bls.Sign, 0, len(v))
				for i := 0; i < len(v); i++ {
					sig := v[i].SignByte(m.hash().Bytes())
					sigs = append(sigs, *sig)
				}
				var aggSig bls.Sign
				aggSig.Aggregate(sigs)
				eProof.AggregatedSignatures = append(eProof.AggregatedSignatures, aggSig)
			}
		}
	}
	return eProof
}

func ValidateEpochActivityProofHerumi(p EpochActivityProofV1Herumi, startHeight uint64, pubKeys []bls.PublicKey) bool {
	beforeTest := time.Now()
	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	aggIndex := 0
	for h := startHeight; h < endHeight; h++ {
		minRound := p.MinRoundsPerHeight[h-startHeight]
		for r := uint64(0); r < uint64(minRound); r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				ok := p.AggregatedSignatures[aggIndex].FastAggregateVerify(pubKeys, m.hash().Bytes())
				if !ok {
					return false
				}
				aggIndex++
			}
		}
	}
	afterTest := time.Now()
	fmt.Println(afterTest.Sub(beforeTest).Seconds())
	return true
}

// we assume there are no omission faults, let's experience the performance over signature verification
func ValidateEpochActivityProofWaitGroupHerumi(p EpochActivityProofV1Herumi, startHeight uint64, pubKeys []bls.PublicKey) bool {
	var wg sync.WaitGroup
	var errorCh = make(chan bool, len(p.AggregatedSignatures))
	mx := sync.RWMutex{}
	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	aggIndex := 0
	beforeTest := time.Now()
	for h := startHeight; h < endHeight; h++ {
		minRound := p.MinRoundsPerHeight[h-startHeight]
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
					ok := p.AggregatedSignatures[i].FastAggregateVerify(pubKeys, h.Bytes())
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
	fmt.Println(afterTest.Sub(beforeTest).Seconds())
	close(errorCh)
	for i := range errorCh {
		return i
	}
	return true
}

func TestVerticalAggregationWithHerumiBLS(t *testing.T) {
	err := bls.Init(bls.BLS12_381)
	require.NoError(t, err)
	committeeSize := 21
	lengthOfEpoch := 60 * 20 // 20 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys := GenerateValidatorsHerumi(committeeSize)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from pi.
	eProof := GenerateEpochActivityProofHerumi(secretKeys, lengthOfEpoch, averageMinRounds)

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofHerumi(eProof, 0, pubKeys)
	if !ok {
		panic(ok)
	}
}

func TestFastVerificationSimulatorWaitGroupHerumiBLS(t *testing.T) {
	err := bls.Init(bls.BLS12_381)
	require.NoError(t, err)
	committeeSize := 21
	lengthOfEpoch := 60 * 10  // 20 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys := GenerateValidatorsHerumi(committeeSize)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from pi.
	eProof := GenerateEpochActivityProofHerumi(secretKeys, lengthOfEpoch, averageMinRounds)

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofWaitGroupHerumi(eProof, 0, pubKeys)
	if !ok {
		panic(ok)
	}
}