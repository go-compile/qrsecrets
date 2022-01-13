package main

import (
	"crypto/elliptic"
	"strings"

	"github.com/go-compile/qrsecrets"

	"github.com/pkg/errors"
)

var (
	// ErrParseBool is returned when a boolean can not be parsed
	ErrParseBool = errors.New("cannot parse boolean")
)

type options struct {
	masterkey string
	plaintext []byte

	file string
	// curve is used when generating a private key
	curve elliptic.Curve
	// encryptKey is used when generating a key
	encryptKey bool

	output string

	hash qrsecrets.HashID

	argonIterations  uint32
	argonMemory      uint32
	argonParallelism uint8
	argonKeyLen      uint32
}

func defaultOptions() *options {
	return &options{
		hash:  qrsecrets.HashSHA256,
		curve: elliptic.P521(),

		argonMemory:      32 * 1024,
		argonIterations:  3,
		argonParallelism: 4,
		argonKeyLen:      32,
	}
}

func parseBool(input string) (bool, error) {
	switch strings.ToLower(input) {
	case "true", "1", "yes", "on", "active", "y":
		return true, nil
	case "false", "0", "no", "off", "disabled", "n":
		return false, nil
	default:
		return false, ErrParseBool
	}
}
