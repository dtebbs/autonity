package bls

import (
	"testing"
	"github.com/clearmatics/autonity/crypto/bls/common"
	// blst "github.com/clearmatics/autonity/crypto/bls/blst"
	// "github.com/clearmatics/autonity/crypto/bls/blst"
	"github.com/stretchr/testify/require"
)

const NUM_VALIDATORS = 21
const NUM_MSGS = 6

func generateValidators(n int) ([]common.BLSSecretKey, []common.BLSPublicKey, error) {
	sk := make([]common.BLSSecretKey, n)
	pk := make([]common.BLSPublicKey, n)
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

func generateMessage(seed byte) ([32]byte) {
	return [32]byte{
		seed, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
	}
}

func genSigsAndPks(
	numMsgs, numSigners, numSignersPerMsg int) (
		[]common.BLSPublicKey, [][]common.BLSSignature, [][32]byte, []uint32, error) {

	var msgs [][32]byte
	var sigs [][]common.BLSSignature
	var msgSigners []uint32

	sks, pks, err := generateValidators(numSigners)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	for i := 0 ; i < numMsgs; i++ {
		msgB := generateMessage(byte(i))
		msgs = append(msgs, msgB)

		// Set of signers as a bit-field
		signers := uint32(0)
		for sigIdx := 0 ; sigIdx < numSignersPerMsg ; sigIdx++ {
			var signerIdx = (i + sigIdx) % numSigners
			signers = signers | (1 << signerIdx)
		}
		msgSigners = append(msgSigners, signers)

		// Signatures (ordered by signer index)
		var sigsForMsg []common.BLSSignature
		for signerIdx := 0 ; signers != 0 ; signerIdx++ {
			if signers & 0x1 == 0x1 {
				var sig = sks[signerIdx].Sign(msgB[:])
				sigsForMsg = append(sigsForMsg, sig)
			}

			signers = signers >> 1;
		}
		sigs = append(sigs, sigsForMsg)
	}

	return pks, sigs, msgs, msgSigners, nil
}

func TestAggregationSingleMessage(t *testing.T) {
	var m = generateMessage(0)
	var sks, pks, _ = generateValidators(NUM_VALIDATORS)

	var sigs = []common.BLSSignature{}
	for i := 0 ; i < len(sks) ; i++ {
		sigs = append(sigs, sks[i].Sign(m[:]))
	}
	var agg_sig = AggregateSignatures(sigs)
	var agg_pk = AggregatePKs(pks, (1 << NUM_VALIDATORS) - 1)

	require.True(t, agg_sig.Verify(agg_pk, m[:]), "verification failed")
}

func TestEpochAggregate(t *testing.T) {
	validators, signatureSets, msgs, msgSigners, _ := genSigsAndPks(
		NUM_MSGS, NUM_VALIDATORS, 15)

	var epochAgg = InitializeEpochAggregate(validators)

	// Assume 10 msgs per block
	const msgs_per_block = 2
	for msgIdx := 0 ; msgIdx < NUM_MSGS ; msgIdx += msgs_per_block {
		AddSignaturesForBlock(
			&epochAgg,
			msgs[msgIdx:(msgIdx + msgs_per_block)],
			msgSigners[msgIdx:(msgIdx + msgs_per_block)],
			signatureSets[msgIdx:(msgIdx + msgs_per_block)])
	}

	require.True(t, VerifyEpochAggregate(epochAgg), "epoch verification failed")
}
