// Package common provides the BLS interfaces that are implemented by the various BLS wrappers.
package common

// SecretKey represents a BLS secret or private key.
type SecretKey interface {
	PublicKey() PublicKey
	Sign(msg []byte) Signature
	Marshal() []byte
	IsZero() bool
}

// PublicKey represents a BLS public key.
type PublicKey interface {
	Marshal() []byte
	Copy() PublicKey
	Aggregate(p2 PublicKey) PublicKey
	IsInfinite() bool
}

// Signature represents a BLS signature.
type Signature interface {
	Verify(pubKey PublicKey, msg []byte) bool
	// Deprecated: Use FastAggregateVerify or use this method in spectests only.
	AggregateVerify(pubKeys []PublicKey, msgs [][32]byte) bool
	FastAggregateVerify(pubKeys []PublicKey, msg [32]byte) bool
	Marshal() []byte
	Copy() Signature
}
