package qrsecrets

import (
	"crypto/sha256"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// HashID represents a hashing algorithm
type HashID uint8

//go:generate stringer -type=HashID
const (
	// HashSHA256 is SHA256
	HashSHA256 HashID = iota
	// HashSHA512 is SHA512
	HashSHA512
	// HashSHA3_256 is SHA3-256
	HashSHA3_256
	// HashSHA3_512 is SHA3-512
	HashSHA3_512
)

//HKDFSHA256 generates a secure key from a secret using hkdf and sha256
func hkdfSha256(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha256.New, secret, nil, nil)

	_, err = io.ReadFull(kdf, key)
	return key, err
}

//hkdfSha512 generates a secure key from a secret using hkdf and sha512
func hkdfSha512(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha512.New, secret, nil, nil)

	_, err = io.ReadFull(kdf, key)
	return key, err
}

//hkdfSha3_256 generates a secure key from a secret using hkdf and sha3-256
func hkdfSha3_256(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha3.New256, secret, nil, nil)

	_, err = io.ReadFull(kdf, key)
	return key, err
}

//hkdfSha3_512 generates a secure key from a secret using hkdf and sha3-512
func hkdfSha3_512(secret []byte) (key []byte, err error) {
	key = make([]byte, 32)
	kdf := hkdf.New(sha3.New512, secret, nil, nil)

	_, err = io.ReadFull(kdf, key)
	return key, err
}

// HashIDToKDF takes a HashID and returns a HKDF function
func HashIDToKDF(hash HashID) func([]byte) ([]byte, error) {
	switch hash {
	case HashSHA256:
		return hkdfSha256
	case HashSHA512:
		return hkdfSha512
	case HashSHA3_256:
		return hkdfSha3_256
	case HashSHA3_512:
		return hkdfSha3_512
	default:
		return nil
	}
}
