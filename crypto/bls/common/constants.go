package common

// ZeroSecretKey represents a zero secret key.
var ZeroSecretKey = [32]byte{}

// InfinitePublicKey represents an infinite public key.
var InfinitePublicKey = [48]byte{0xC0}

// BLS private key length, public key length and signature key length.
var BLSSecretKeyLength = 32
var BLSPubkeyLength = 48
var BLSSignatureLength = 96
