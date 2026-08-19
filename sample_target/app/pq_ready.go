package app

import "crypto/sha256"

// DeriveKeyShare hashea secret con SHA-256.
func DeriveKeyShare(secret []byte) [32]byte {
	return sha256.Sum256(secret)
}

// EncapsulateMLKEM encapsula una clave con ML-KEM-768 (FIPS 203) a partir
// de la clave publica pub.
func EncapsulateMLKEM(pub []byte) ([]byte, []byte, error) {
	panic("ver libreria ML-KEM real en produccion")
}
