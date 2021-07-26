package bls

import (
	"github.com/clearmatics/autonity/crypto/bls/common"
)

// NOTE!! For demonstration purposes only.

type EpochAggregate struct {
	// List of validators for the epoch
	validators []common.BLSPublicKey

	// all messages / digests
	msgs [][32]byte

	// bit field representing which validators signed each message
	msg_signers []uint32

	// aggregated signature
	sig common.BLSSignature
}

/// Initialize with the ordered set of public keys for all signers of
/// messages during the epoch
func InitializeEpochAggregate(validators []common.BLSPublicKey) (EpochAggregate) {
	// TODO: Initialize sig to the zero element, to simplify the accumulation code.
	return EpochAggregate{
		validators: validators,
		msgs: [][32]byte{},
		msg_signers: []uint32{},
		// sig: BLSSignature{},
	}
}

/// If the set of signers is {P1, P2, P3, P4}, the first message is
/// signed by P1, P2, and P3 and the second message is signed by P2 P3
/// and P4, arguments should be:
///
///  msgs        = { msg1, msg2 }
///  msg_signers = { 0111b, 1110b }  (bit-fields showing who signed each message)
///  signatures  = { {sig_p1_msg1, sig_p2_msg1, sig_p3_msg3},
///                  {sig_p2_msg2, sig_p3_msg2, sig_p4_msg2},
///                }
func AddSignaturesForBlock(
	epochAgg *EpochAggregate,
	msgs [][32]byte,
	msg_signers	[]uint32,
	signatures [][]common.BLSSignature) {

	// For each msg, aggregate signatures and keys
	for i := 0 ; i < len(msgs) ; i++ {
		epochAgg.msgs = append(epochAgg.msgs, msgs[i])
		epochAgg.msg_signers = append(epochAgg.msg_signers, msg_signers[i])
		epochAgg.sig = aggregateSignatures(epochAgg.sig, signatures[i])
	}
}

/// Verify an aggreagted signature over a full epoch. In production,
/// the aggregated public keys should be computed in advance (as the
/// set of signers for each message is determined), via AggregatePKs,
/// and called in advance.
func VerifyEpochAggregate(epochAgg EpochAggregate) (bool) {

	// Aggreagte the public keys
	var aggPKs = []common.BLSPublicKey{}
	for i := 0 ; i < len(epochAgg.msgs) ; i++ {
		var aggPK = AggregatePKs(epochAgg.validators, epochAgg.msg_signers[i])
		aggPKs = append(aggPKs, aggPK)
	}

	return epochAgg.sig.AggregateVerify(aggPKs, epochAgg.msgs)
}

func AggregatePKs(all_pks []common.BLSPublicKey, keys_present uint32) (common.BLSPublicKey) {
	// If this could be set to the "zero" element of the group, the
	// code here could be simplified. For now, search for the first
	// signer and assign his public key to `agg`, then iterate through
	// the remaining signers.
	var agg common.BLSPublicKey

	var pk_idx = 0

	// Search for first signer index
	for (keys_present & 0x1) == 0 {
		pk_idx++
		keys_present = keys_present >> 1
	}

	agg = all_pks[pk_idx]
	pk_idx++
	keys_present = keys_present >> 1

	for keys_present != 0 {
		if (keys_present & 0x1) == 0x1 {
			agg.Aggregate(all_pks[pk_idx])
		}

		pk_idx++
		keys_present = keys_present >> 1
	}

	return agg
}

func aggregateSignatures(
	agg common.BLSSignature,
	sigs []common.BLSSignature) (common.BLSSignature) {
	if agg == nil {
		return AggregateSignatures(sigs)
	}

	return AggregateSignatures(
		[]common.BLSSignature{agg, AggregateSignatures(sigs)})
}
