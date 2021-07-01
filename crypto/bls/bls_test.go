package bls

import (
	"bytes"
	"crypto/ecdsa"
	"github.com/clearmatics/autonity/crypto/secp256k1"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"

	"crypto/rand"
	"github.com/clearmatics/autonity/crypto/bls/common"
)

func TestDisallowZeroSecretKeys(t *testing.T) {
	t.Run("blst", func(t *testing.T) {
		// Blst does a zero check on the key during deserialization.
		_, err := SecretKeyFromBytes(common.ZeroSecretKey[:])
		require.Equal(t, common.ErrSecretUnmarshal, err)
	})
}

func TestDisallowZeroPublicKeys(t *testing.T) {
	t.Run("blst", func(t *testing.T) {
		_, err := PublicKeyFromBytes(common.InfinitePublicKey[:])
		require.Equal(t, common.ErrInfinitePubKey, err)
	})
}

func TestDisallowZeroPublicKeys_AggregatePubkeys(t *testing.T) {
	t.Run("blst", func(t *testing.T) {
		_, err := AggregatePublicKeys([][]byte{common.InfinitePublicKey[:], common.InfinitePublicKey[:]})
		require.Equal(t, common.ErrInfinitePubKey, err)
	})
}

func TestValidateSecretKeyString(t *testing.T) {
	t.Run("blst", func(t *testing.T) {
		zeroNum := new(big.Int).SetUint64(0)
		_, err := SecretKeyFromBigNum(zeroNum.String())
		require.NotNil(t, err)

		randBytes := make([]byte, 40)
		n, err := rand.Read(randBytes)
		require.NoError(t, err)
		require.Equal(t, n, len(randBytes))
		rBigNum := new(big.Int).SetBytes(randBytes)

		// Expect larger than expected key size to fail.
		_, err = SecretKeyFromBigNum(rBigNum.String())
		require.NotNil(t, err)

		key, err := RandKey()
		require.NoError(t, err)
		rBigNum = new(big.Int).SetBytes(key.Marshal())

		// Expect correct size to pass.
		_, err = SecretKeyFromBigNum(rBigNum.String())
		require.NoError(t, err)
	})
}

func TestReuseECDSAKeyForBLS(t *testing.T) {
	// new ecdsa key, it is a 32 bytes random number.
	ecdsaKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	require.NoError(t, err)

	blsPrivateKey, err := SecretKeyFromECDSAKey(ecdsaKey)
	require.NoError(t, err)

	for i := 0; i < 100; i++ {
		// use ecdsa key, to elicit a deterministic private key of bls.
		skNewGenerated, err := SecretKeyFromECDSAKey(ecdsaKey)
		require.NoError(t, err)

		// check the deterministic property.
		require.Equal(t, true, bytes.Equal(blsPrivateKey.Marshal(), skNewGenerated.Marshal()))

		// check basic features of bls signature signing and verification.
		pk := skNewGenerated.PublicKey()
		msg := []byte("hello world!")
		sig := skNewGenerated.Sign(msg)
		require.Equal(t, true, sig.Verify(pk, msg))
	}
}
