package main

import (
	"crypto/elliptic"
	"qrsecrets"
	"strings"

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
}

func defaultOptions() *options {
	return &options{
		hash:  qrsecrets.HashSHA256,
		curve: elliptic.P521(),
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
