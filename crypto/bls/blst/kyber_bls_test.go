package blst

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/clearmatics/autonity/common"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/util/random"
	"sync"
	"testing"
	"time"

	"go.dedis.ch/kyber/v3"
)

type hashablePoint interface {
	Hash([]byte) kyber.Point
}

// NewKeyPair creates a new BLS signing key pair. The private key x is a scalar
// and the public key X is a point on curve G2.
func NewKeyPair(suite pairing.Suite, random cipher.Stream) (kyber.Scalar, kyber.Point) {
	x := suite.G2().Scalar().Pick(random)
	X := suite.G2().Point().Mul(x, nil)
	return x, X
}

// Sign creates a BLS signature S = x * H(m) on a message m using the private
// key x. The signature S is a point on curve G1.
func Sign(suite pairing.Suite, x kyber.Scalar, msg []byte) ([]byte, error) {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return nil, errors.New("point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	xHM := HM.Mul(x, HM)

	s, err := xHM.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Verify checks the given BLS signature S on the message m using the public
// key X by verifying that the equality e(H(m), X) == e(H(m), x*B2) ==
// e(x*H(m), B2) == e(S, B2) holds where e is the pairing operation and B2 is
// the base point from curve G2.
func Verify(suite pairing.Suite, X kyber.Point, msg, sig []byte) error {
	hashable, ok := suite.G1().Point().(hashablePoint)
	if !ok {
		return errors.New("bls: point needs to implement hashablePoint")
	}
	HM := hashable.Hash(msg)
	left := suite.Pair(HM, X)
	s := suite.G1().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return err
	}
	right := suite.Pair(s, suite.G2().Point().Base())
	if !left.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}

// AggregateSignatures combines signatures created using the Sign function
func AggregateSignaturesKyber(suite pairing.Suite, sigs ...[]byte) ([]byte, error) {
	sig := suite.G1().Point()
	for _, sigBytes := range sigs {
		sigToAdd := suite.G1().Point()
		if err := sigToAdd.UnmarshalBinary(sigBytes); err != nil {
			return nil, err
		}
		sig.Add(sig, sigToAdd)
	}
	return sig.MarshalBinary()
}

func distinct(msgs [][]byte) bool {
	m := make(map[[32]byte]bool)
	for _, msg := range msgs {
		h := sha256.Sum256(msg)
		if m[h] {
			return false
		}
		m[h] = true
	}
	return true
}

// BatchVerify verifies a large number of publicKey/msg pairings with a single aggregated signature.
// Since aggregation is generally much faster than verification, this can be a speed enhancement.
// Benchmarks show a roughly 50% performance increase over individual signature verification
// Every msg must be unique or there is the possibility to accept an invalid signature
// see: https://crypto.stackexchange.com/questions/56288/is-bls-signature-scheme-strongly-unforgeable/56290
// for a description of why each message must be unique.
func BatchVerify(suite pairing.Suite, publics []kyber.Point, msgs [][]byte, sig []byte) error {
	if !distinct(msgs) {
		return fmt.Errorf("bls: error, messages must be distinct")
	}

	s := suite.G1().Point()
	if err := s.UnmarshalBinary(sig); err != nil {
		return err
	}

	var aggregatedLeft kyber.Point
	for i := range msgs {
		hashable, ok := suite.G1().Point().(hashablePoint)
		if !ok {
			return errors.New("bls: point needs to implement hashablePoint")
		}
		hm := hashable.Hash(msgs[i])
		pair := suite.Pair(hm, publics[i])

		if i == 0 {
			aggregatedLeft = pair
		} else {
			aggregatedLeft.Add(aggregatedLeft, pair)
		}
	}

	right := suite.Pair(s, suite.G2().Point().Base())
	if !aggregatedLeft.Equal(right) {
		return errors.New("bls: invalid signature")
	}
	return nil
}

// AggregatePublicKeys takes a slice of public G2 points and returns
// the sum of those points. This is used to verify multisignatures.
func AggregatePublicKeysKyber(suite pairing.Suite, Xs ...kyber.Point) kyber.Point {
	aggregated := suite.G2().Point()
	for _, X := range Xs {
		aggregated.Add(aggregated, X)
	}
	return aggregated
}

type EpochActivityProofV1Kyber struct {
	MinRoundsPerHeight []int // min round number of each height from 1st height to the last height of the Epoch.
	// Todo: for actual signatures we would need to make sure that they are ordered otherwise the verification can fail
	AggregatedSignatures [][]byte             // the aggregated msg signature of per voting steps, sorted by height, round and steps.
	Absences             []AbsentParticipants // the set of validators that are not participated on a specific voting step.
}

func GenerateValidatorsKyber(n int) ([]kyber.Scalar, []kyber.Point) {
	suite := bn256.NewSuite()
	sk := make([]kyber.Scalar, n)
	pk := make([]kyber.Point, n)
	for i := 0; i < n; i++ {
		s, p := NewKeyPair(suite, random.New())
		sk[i] = s
		pk[i] = p
	}
	return sk, pk
}

// generate a full view of the entire proof of activities, let's assume there are no omission.
func GenerateEpochActivityProofKyber(v []kyber.Scalar, epochLength int, avgRound int) EpochActivityProofV1Kyber {
	suite := bn256.NewSuite()
	endHeight := uint64(epochLength)
	eProof := EpochActivityProofV1Kyber{}
	for h := uint64(0); h < endHeight; h++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
		for r := uint64(0); r < uint64(avgRound); r++ {
			for s := uint8(0); s < uint8(2); s++ {
				m := Msg{
					H: h,
					R: r,
					S: s,
				}
				sigs := make([][]byte, 0, len(v))
				for i := 0; i < len(v); i++ {
					sig, err := Sign(suite, v[i], m.hash().Bytes())
					if err != nil {
						panic(err)
					}
					sigs = append(sigs, sig)
				}
				aggSig, err := AggregateSignaturesKyber(suite, sigs...)
				if err != nil {
					panic(err)
				}
				eProof.AggregatedSignatures = append(eProof.AggregatedSignatures, aggSig)
			}
		}
	}
	return eProof
}

// we assume there are no omission faults, let's experience the performance over signature verification
func ValidateEpochActivityProofKyber(p EpochActivityProofV1Kyber, startHeight uint64, pubKeys []kyber.Point) bool {
	suite := bn256.NewSuite()
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

				aggregatedKey := AggregatePublicKeysKyber(suite, pubKeys...)

				err := Verify(suite, aggregatedKey, m.hash().Bytes(), p.AggregatedSignatures[aggIndex])
				if err != nil {
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
func ValidateEpochActivityProofWaitGroupKyber(p EpochActivityProofV1Kyber, startHeight uint64, pubKeys []kyber.Point) bool {
	suite := bn256.NewSuite()
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
					aggregatedKey := AggregatePublicKeysKyber(suite, pubKeys...)
					err := Verify(suite, aggregatedKey, m.hash().Bytes(), p.AggregatedSignatures[i])
					mx.RUnlock()
					if err != nil {
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

func TestFastVerificationSimulatorKyber(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 60 * 10 // 10 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys := GenerateValidatorsKyber(committeeSize)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from pi.
	eProof := GenerateEpochActivityProofKyber(secretKeys, lengthOfEpoch, averageMinRounds)

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofKyber(eProof, 0, pubKeys)
	if !ok {
		panic(ok)
	}
}

func TestFastVerificationSimulatorWaitGroupKyber(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 60 * 10 // 10 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys, err := GenerateValidators(committeeSize)
	require.NoError(t, err)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from pi.
	eProof := GenerateEpochActivityProof(secretKeys, lengthOfEpoch, averageMinRounds)

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofWaitGroup(eProof, 0, pubKeys)
	if !ok {
		panic(ok)
	}
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// horizontal agg test with kyber lib.
// the overview of the activities for the entire epoch, it will be submit by Pi.
type EpochActivityProofV2Kyber struct {
	MinRoundsPerHeight      []uint64                      // min round number of each height from 1st height to the last height of the Epoch.
	CommitteeActivityProofs []ValidatorActivityProofKyber // each for per validator.
}

// the activity proof of a specific validator.
type ValidatorActivityProofKyber struct {
	ValidatorIndex int    // the validator index.
	AggSignature   []byte // the aggregated msg signature of the entire epoch of this validator, sorted by
	// pattern: height, round, step
	MissedMsgs []Msg // missing msgs of this validator, sorted by height, round and step.
}

// generate a full view of the entire proof of activities, let's assume there are no omission.
func GenerateEpochActivityProofV2Kyber(v []kyber.Scalar, epochLength int, avgRound uint64) EpochActivityProofV2Kyber {
	suite := bn256.NewSuite()
	eProof := EpochActivityProofV2Kyber{}
	// set the minimum round to avg minimum round: 2, for each height
	for i := 0; i < epochLength; i++ {
		eProof.MinRoundsPerHeight = append(eProof.MinRoundsPerHeight, avgRound)
	}

	// assume there are no omission, so we aggregate all the msg sent by each validator.
	for i := 0; i < len(v); i++ {
		sigs := make([][]byte, 0, epochLength*int(avgRound)*2)
		for h := uint64(0); h < uint64(epochLength); h++ {
			for r := uint64(0); r < avgRound; r++ {
				for s := uint8(0); s < 2; s++ {
					m := Msg{
						H: h,
						R: r,
						S: s,
					}
					sig, err := Sign(suite, v[i], m.hash().Bytes())
					if err != nil {
						panic(err)
					}
					sigs = append(sigs, sig)
				}
			}
		}
		agg, err := AggregateSignaturesKyber(suite, sigs...)
		if err != nil {
			panic(err)
		}

		validatorP := ValidatorActivityProofKyber{
			ValidatorIndex: i,
			AggSignature:   agg,
			MissedMsgs:     nil,
		}
		eProof.CommitteeActivityProofs = append(eProof.CommitteeActivityProofs, validatorP)
	}

	return eProof
}

func ValidateEpochActivityProofV2Kyber(p EpochActivityProofV2Kyber, startHeight uint64, pubKeys []kyber.Point) bool {
	suite := bn256.NewSuite()
	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	beforeTest := time.Now()
	for i := 0; i < len(p.CommitteeActivityProofs); i++ {
		pKey := pubKeys[p.CommitteeActivityProofs[i].ValidatorIndex]
		aggSig := p.CommitteeActivityProofs[i].AggSignature
		// there is no missing msg, then to re-create all the msgs.
		keys := make([]kyber.Point, 0, epochLength*2*2)
		msgs := make([][]byte, 0, epochLength*2*2)
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
					msgs = append(msgs, m.hash().Bytes())
				}
			}
		}
		err := BatchVerify(suite, keys, msgs, aggSig)
		if err != nil {
			return false
		}
	}
	afterTest := time.Now()
	fmt.Println(afterTest.Sub(beforeTest).Seconds())
	return true
}

func ValidateEpochActivityProofV2WaitGroupKyber(p EpochActivityProofV2Kyber, startHeight uint64, pubKeys []kyber.Point) bool {
	suite := bn256.NewSuite()
	var wg sync.WaitGroup
	var errorCh = make(chan bool, len(p.CommitteeActivityProofs))

	epochLength := len(p.MinRoundsPerHeight)
	endHeight := startHeight + uint64(epochLength)
	beforeTest := time.Now()

	for i := 0; i < len(p.CommitteeActivityProofs); i++ {
		pKey := pubKeys[p.CommitteeActivityProofs[i].ValidatorIndex]
		aggSig := p.CommitteeActivityProofs[i].AggSignature
		// there is no missing msg, then to re-create all the msgs.
		keys := make([]kyber.Point, 0, epochLength*2*2)
		msgs := make([][]byte, 0, epochLength*2*2)
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
					msgs = append(msgs, m.hash().Bytes())
				}
			}
		}

		wg.Add(1)
		go func(ks []kyber.Point, ms [][]byte) {
			defer wg.Done()
			err := BatchVerify(suite, ks, ms, aggSig)
			if err != nil {
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

func TestOneAggSignaturePerNodeSimulatorKyber(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 60 * 20 // 20 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys := GenerateValidatorsKyber(committeeSize)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from Pi.
	eProof := GenerateEpochActivityProofV2Kyber(secretKeys, lengthOfEpoch, uint64(averageMinRounds))

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofV2Kyber(eProof, uint64(0), pubKeys)
	require.True(t, ok)
}

func TestOneAggSignaturePerNodeSimulatorWaitGroupKyber(t *testing.T) {
	committeeSize := 21
	lengthOfEpoch := 60 * 20 // 20 minutes.
	averageMinRounds := 2    // we assume there at least have 2 rounds for each height to make the decision.
	secretKeys, pubKeys := GenerateValidatorsKyber(committeeSize)

	// now we generate the epoch proof for a single validator, and verify it. In production case, there would be multiple
	// ones for verification since all the validator will submit a proof for an epoch.

	// generate the entire proof of activity of the epoch from Pi.
	eProof := GenerateEpochActivityProofV2Kyber(secretKeys, lengthOfEpoch, uint64(averageMinRounds))

	// validate the proof sent by pi.
	ok := ValidateEpochActivityProofV2WaitGroupKyber(eProof, uint64(0), pubKeys)
	require.True(t, ok)
}

/*

func TestBLS(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	err = Verify(suite, public, msg, sig)
	require.Nil(t, err)
}

func TestBLSFailSig(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, public := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	sig[0] ^= 0x01
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSFailKey(t *testing.T) {
	msg := []byte("Hello Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	sig, err := Sign(suite, private, msg)
	require.Nil(t, err)
	_, public := NewKeyPair(suite, random.New())
	if Verify(suite, public, msg, sig) == nil {
		t.Fatal("bls: verification succeeded unexpectedly")
	}
}

func TestBLSBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg1)
	require.Nil(t, err)
	sig2, err := Sign(suite, private2, msg2)
	require.Nil(t, err)
	aggregatedSig, err := AggregateSignaturesKyber(suite, sig1, sig2)
	require.Nil(t, err)

	err = BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig)
	require.Nil(t, err)
}

func TestBLSFailBatchVerify(t *testing.T) {
	msg1 := []byte("Hello Boneh-Lynn-Shacham")
	msg2 := []byte("Hello Dedis & Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	sig1, err := Sign(suite, private1, msg1)
	require.Nil(t, err)
	sig2, err := Sign(suite, private2, msg2)
	require.Nil(t, err)

	t.Run("fails with a bad signature", func(t *testing.T) {
		aggregatedSig, err := AggregateSignaturesKyber(suite, sig1, sig2)
		require.Nil(t, err)
		msg2[0] ^= 0x01
		if BatchVerify(suite, []kyber.Point{public1, public2}, [][]byte{msg1, msg2}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

	t.Run("fails with a duplicate msg", func(t *testing.T) {
		private3, public3 := NewKeyPair(suite, random.New())
		sig3, err := Sign(suite, private3, msg1)
		require.Nil(t, err)
		aggregatedSig, err := AggregateSignaturesKyber(suite, sig1, sig2, sig3)
		require.Nil(t, err)

		if BatchVerify(suite, []kyber.Point{public1, public2, public3}, [][]byte{msg1, msg2, msg1}, aggregatedSig) == nil {
			t.Fatal("bls: verification succeeded unexpectedly")
		}
	})

}

func BenchmarkBLSKeyCreation(b *testing.B) {
	suite := bn256.NewSuite()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewKeyPair(suite, random.New())
	}
}

func BenchmarkBLSSign(b *testing.B) {
	suite := bn256.NewSuite()
	private, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sign(suite, private, msg)
	}
}

func BenchmarkBLSAggregateSigs(b *testing.B) {
	suite := bn256.NewSuite()
	private1, _ := NewKeyPair(suite, random.New())
	private2, _ := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AggregateSignaturesKyber(suite, sig1, sig2)
	}
}

func BenchmarkBLSVerifyAggregate(b *testing.B) {
	suite := bn256.NewSuite()
	private1, public1 := NewKeyPair(suite, random.New())
	private2, public2 := NewKeyPair(suite, random.New())
	msg := []byte("Hello many times Boneh-Lynn-Shacham")
	sig1, err := Sign(suite, private1, msg)
	require.Nil(b, err)
	sig2, err := Sign(suite, private2, msg)
	require.Nil(b, err)
	sig, err := AggregateSignaturesKyber(suite, sig1, sig2)
	key := AggregatePublicKeysKyber(suite, public1, public2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(suite, key, msg, sig)
	}
}

func BenchmarkBLSVerifyBatchVerify(b *testing.B) {
	suite := bn256.NewSuite()

	numSigs := 100
	privates := make([]kyber.Scalar, numSigs)
	publics := make([]kyber.Point, numSigs)
	msgs := make([][]byte, numSigs)
	sigs := make([][]byte, numSigs)
	for i := 0; i < numSigs; i++ {
		private, public := NewKeyPair(suite, random.New())
		privates[i] = private
		publics[i] = public
		msg := make([]byte, 64, 64)
		rand.Read(msg)
		msgs[i] = msg
		sig, err := Sign(suite, private, msg)
		require.Nil(b, err)
		sigs[i] = sig
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggregateSig, _ := AggregateSignaturesKyber(suite, sigs...)
		BatchVerify(suite, publics, msgs, aggregateSig)
	}
}

func TestBinaryMarshalAfterAggregation_issue400(t *testing.T) {
	suite := bn256.NewSuite()

	_, public1 := NewKeyPair(suite, random.New())
	_, public2 := NewKeyPair(suite, random.New())

	workingKey := AggregatePublicKeysKyber(suite, public1, public2, public1)

	workingBits, err := workingKey.MarshalBinary()
	require.Nil(t, err)

	workingPoint := suite.G2().Point()
	err = workingPoint.UnmarshalBinary(workingBits)
	require.Nil(t, err)

	// this was failing before the fix
	aggregatedKey := AggregatePublicKeysKyber(suite, public1, public1, public2)

	bits, err := aggregatedKey.MarshalBinary()
	require.Nil(t, err)

	point := suite.G2().Point()
	err = point.UnmarshalBinary(bits)
	require.Nil(t, err)
}*/
