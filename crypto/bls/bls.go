package bls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"github.com/clearmatics/autonity/crypto/secp256k1"
	blst "github.com/supranational/blst/bindings/go"
)

type PublicKey = blst.P1Affine
type Signature = blst.P2Affine
type AggregateSignature = blst.P2Aggregate
type AggregatePublicKey = blst.P1Aggregate

func blsTest() error {

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
		pk := new(PublicKey).From(skNewGenerated)
		var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")
		msg := []byte("hello world!")
		sig := new(Signature).Sign(skNewGenerated, msg, dst)

		if !sig.Verify(true, pk, true, msg, dst) {
			fmt.Println("ERROR: Invalid!")
		} else {
			fmt.Println("Valid!")
		}
	}
	return nil
}
