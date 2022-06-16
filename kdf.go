package qrsecrets

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

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

// HashIDToKDF takes a HashID and returns a HKDF function
func HashIDToKDF(hash HashID) hash.Hash {
	switch hash {
	case HashSHA256:
		return sha256.New()
	case HashSHA512:
		return sha512.New()
	case HashSHA3_256:
		return sha3.New256()
	case HashSHA3_512:
		return sha3.New512()
	default:
		return nil
	}
}
