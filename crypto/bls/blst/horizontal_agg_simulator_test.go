package blst

import "github.com/clearmatics/autonity/crypto/bls/common"

// the overview of the activities for the entire epoch, it will be submit by Pi.
type EpochActivityProofV2 struct {
	MinRoundsPerHeight []int64 // min round number of each height from 1st height to the last height of the Epoch.
	CommitteeActivityProofs []ValidatorActivityProof
}

type ValidatorActivityProof struct {
	ValidatorIndex int
	AggSignature common.BLSSignature
	MissedMsgs []Msg
}
