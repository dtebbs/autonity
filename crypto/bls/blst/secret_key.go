package blst

import (
	"crypto/rand"
	"fmt"
	"github.com/clearmatics/autonity/crypto/bls/common"
	blst "github.com/supranational/blst/bindings/go"
)

// bls12SecretKey used in the BLS signature scheme.
type bls12SecretKey struct {
	p *blst.SecretKey
}

// RandKey creates a new private key using a random method provided as an io.Reader.
func RandKey() (common.BLSSecretKey, error) {
	// Generate 32 bytes of randomness
	var ikm [32]byte
	_, err := rand.Read(ikm[:])
	if err != nil {
		return nil, err
	}
	// Defensive check, that we have not generated a secret key,
	secKey := &bls12SecretKey{blst.KeyGen(ikm[:])}
	if secKey.IsZero() {
		return nil, common.ErrZeroKey
	}
	return secKey, nil
}

func SecretKeyFromECDSAKey(ecdsaKey []byte) (common.BLSSecretKey, error) {
	if len(ecdsaKey) != common.ECDSASecretKeyLength {
		return nil, fmt.Errorf("secret key must be %d bytes", common.ECDSASecretKeyLength)
	}

	blsSK := blst.KeyGen(ecdsaKey)
	if blsSK == nil {
		return nil, common.ErrSecretConvert
	}

	wrappedKey := &bls12SecretKey{p: blsSK}
	if wrappedKey.IsZero() {
		return nil, common.ErrZeroKey
	}
	return wrappedKey, nil
}

// SecretKeyFromBytes creates a BLS private key from a BigEndian byte slice.
func SecretKeyFromBytes(privKey []byte) (common.BLSSecretKey, error) {
	if len(privKey) != common.BLSSecretKeyLength {
		return nil, fmt.Errorf("secret key must be %d bytes", common.BLSSecretKeyLength)
	}
	secKey := new(blst.SecretKey).Deserialize(privKey)
	if secKey == nil {
		return nil, common.ErrSecretUnmarshal
	}
	wrappedKey := &bls12SecretKey{p: secKey}
	if wrappedKey.IsZero() {
		return nil, common.ErrZeroKey
	}
	return wrappedKey, nil
}

// BLSPublicKey obtains the public key corresponding to the BLS secret key.
func (s *bls12SecretKey) PublicKey() common.BLSPublicKey {
	return &PublicKey{p: new(blstPublicKey).From(s.p)}
}

// IsZero checks if the secret key is a zero key.
func (s *bls12SecretKey) IsZero() bool {
	zeroKey := new(blst.SecretKey)
	return s.p.Equals(zeroKey)
}

// Sign a message using a secret key - in a beacon/validator client.
//
// In IETF draft BLS specification:
// Sign(SK, message) -> signature: a signing algorithm that generates
//      a deterministic signature given a secret key SK and a message.
//
// In ETH2.0 specification:
// def Sign(SK: int, message: Bytes) -> BLSSignature
func (s *bls12SecretKey) Sign(msg []byte) common.BLSSignature {
	signature := new(blstSignature).Sign(s.p, msg, dst)
	return &Signature{s: signature}
}

// Marshal a secret key into a LittleEndian byte slice.
func (s *bls12SecretKey) Marshal() []byte {
	keyBytes := s.p.Serialize()
	if len(keyBytes) < common.BLSSecretKeyLength {
		emptyBytes := make([]byte, common.BLSSecretKeyLength-len(keyBytes))
		keyBytes = append(emptyBytes, keyBytes...)
	}
	return keyBytes
}
