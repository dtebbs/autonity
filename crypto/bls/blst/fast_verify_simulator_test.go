package blst

import (
	"github.com/clearmatics/autonity/common"
	"github.com/clearmatics/autonity/core/types"
	bls "github.com/clearmatics/autonity/crypto/bls/common"
	"github.com/clearmatics/autonity/rlp"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

/*
  Vertical Aggregation:
  Aggregate all the signatures of same Msg that signed by members of committee, then save the aggregated signature into
  a slice that is order by height, round, and step.

  Msg < H, R, S> => (Sig_N1, Sig_N2, ... Sin_N) => AggSig_h_r_s.

  Save AggSig_h_r_s into a slice that is order by h, r and s.

  Pro: less computing cost.
  Con: relevant higher storage cost.
*/

// the overview of the activities for the entire epoch, it will be submit by Pi.
type EpochActivityProofV1 struct {
	MinRoundsPerHeight   []int                // min round number of each height from 1st height to the last height of the Epoch.
	AggregatedSignatures []bls.BLSSignature   // the aggregated msg signature of per voting steps, sorted by height, round and steps.
	Absences             []AbsentParticipants // the set of validators that are not participated on a specific voting step.
}

// the missing participant information of a specific voting step.
type AbsentParticipants struct {
	Msg
	AbsentValidators []int // the index of validators from which that the msg is not received after the delay of delta.
}

// a specific voting step.
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

// generate a full view of the entire proof of activities, let's assume there are no omission.
func GenerateEpochActivityProof(v []bls.BLSSecretKey, epochLength int, avgRound int) EpochActivityProofV1 {
	endHeight := uint64(epochLength)
	eProof := EpochActivityProofV1{}
	for h := uint64(0); h < endHeight; h++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
		for r := uint64(0); r < uint64(avgRound); r++ {
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
	return eProof
}

// we assume there are no omission faults, let's experience the performance over signature verification
func ValidateEpochActivityProof(p EpochActivityProofV1, startHeight uint64, pubKeys []bls.BLSPublicKey) bool {
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
				ok := p.AggregatedSignatures[aggIndex].FastAggregateVerify(pubKeys, m.hash())
				if !ok {
					return false
				}
				aggIndex++
			}
		}
	}
	return true
}

func TestFastVerificationSimulator(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 60 * 20 // 20 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	require.NoError(t, err)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from pi.
	eProof := GenerateEpochActivityProof(secretKeys, lengthOfEpoch, averageMinRounds)

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProof(eProof, 0, pubKeys)
	if !ok {
		panic(ok)
	}
}
