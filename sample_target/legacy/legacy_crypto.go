package legacy

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rsa"
	"crypto/rand"
)

// GenerateSigningKey genera un par de claves RSA de 2048 bits.
func GenerateSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// HashPassword hashea password con MD5.
func HashPassword(password []byte) [16]byte {
	return md5.Sum(password)
}

// NewLegacyCipher crea un cifrador DES con la clave dada.
func NewLegacyCipher(key []byte) (interface{}, error) {
	return des.NewCipher(key)
}
