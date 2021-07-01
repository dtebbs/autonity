package bls

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/clearmatics/autonity/crypto/bls/blst"
	"github.com/clearmatics/autonity/crypto/bls/common"
	"github.com/pkg/errors"
)

// SecretKeyFromECDSAKey create a BLS private key from a ECDSA private key.
func SecretKeyFromECDSAKey(sk *ecdsa.PrivateKey) (SecretKey, error) {
	return blst.SecretKeyFromECDSAKey(sk.D.Bytes())
}

// SecretKeyFromBytes creates a BLS private key from a BigEndian byte slice.
func SecretKeyFromBytes(privKey []byte) (SecretKey, error) {
	return blst.SecretKeyFromBytes(privKey)
}

// SecretKeyFromBigNum takes in a big number string and creates a BLS private key.
func SecretKeyFromBigNum(s string) (SecretKey, error) {
	num := new(big.Int)
	num, ok := num.SetString(s, 10)
	if !ok {
		return nil, errors.New("could not set big int from string")
	}
	bts := num.Bytes()
	if len(bts) != 32 {
		return nil, errors.Errorf("provided big number string sets to a key unequal to 32 bytes: %d != 32", len(bts))
	}
	return SecretKeyFromBytes(bts)
}

// PublicKeyFromBytes creates a BLS public key from a  BigEndian byte slice.
func PublicKeyFromBytes(pubKey []byte) (PublicKey, error) {
	return blst.PublicKeyFromBytes(pubKey)
}

// SignatureFromBytes creates a BLS signature from a LittleEndian byte slice.
func SignatureFromBytes(sig []byte) (Signature, error) {
	return blst.SignatureFromBytes(sig)
}

// AggregatePublicKeys aggregates the provided raw public keys into a single key.
func AggregatePublicKeys(pubs [][]byte) (PublicKey, error) {
	return blst.AggregatePublicKeys(pubs)
}

// AggregateSignatures converts a list of signatures into a single, aggregated sig.
func AggregateSignatures(sigs []common.BLSSignature) common.BLSSignature {
	return blst.AggregateSignatures(sigs)
}

// VerifyMultipleSignatures verifies multiple signatures for distinct messages securely.
func VerifyMultipleSignatures(sigs [][]byte, msgs [][32]byte, pubKeys []common.BLSPublicKey) (bool, error) {
	return blst.VerifyMultipleSignatures(sigs, msgs, pubKeys)
}

// NewAggregateSignature creates a blank aggregate signature.
func NewAggregateSignature() common.BLSSignature {
	return blst.NewAggregateSignature()
}

// RandKey creates a new private key using a random input.
func RandKey() (common.BLSSecretKey, error) {
	return blst.RandKey()
}

/*
import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/clearmatics/autonity/crypto/secp256k1"
	blst "github.com/supranational/blst/bindings/go"
)

type BLSPublicKey = blst.P1Affine
type BLSSignature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

func reuseECDSAKeyForBLSTest() error {

	// new ecdsa key, it is a 32 bytes random number.
	ecdsaKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return err
	}

	// generate a bls key by using ecdsa key.
	blsSK1stGenerated := blst.KeyGen(ecdsaKey.D.Bytes())

	for i:= 0; i < 10000000; i++ {
		// use ecdsa key, to elicit a deterministic private key of bls.
		keyBytes := ecdsaKey.D.Bytes()
		skNewGenerated := blst.KeyGen(keyBytes)

		// check the deterministic property.
		if *blsSK1stGenerated != *skNewGenerated {
			panic("not deterministic")
		}

		// check basic features of bls signature signing and verification.
		pk := new(BLSPublicKey).From(skNewGenerated)
		var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
		msg := []byte("hello world!")
		sig := new(BLSSignature).Sign(skNewGenerated, msg, dst)

		if !sig.Verify(true, pk, true, msg, dst) {
			fmt.Println("ERROR: Invalid!")
		} else {
			fmt.Println("Valid!")
		}
	}
	return nil
}*/
