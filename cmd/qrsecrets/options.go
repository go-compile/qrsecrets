package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/go-compile/qrsecrets"
	"github.com/skip2/go-qrcode"

	"github.com/pkg/errors"
)

var (
	// ErrParseBool is returned when a boolean can not be parsed
	ErrParseBool = errors.New("cannot parse boolean")
)

// Used for symmetric only option. ECDSA-P256
const (
	defaultKeyD = "3468b92f287ce872e1c579bc3601eb839f75e8c70047dd254d91e6dce166d962"
	defaultKeyX = "14e6e221d384111b30b1ba36f2b566045df07f5ef454404dff232da5097eaad9"
	defaultKeyY = "dc677dbf013df12c477e133ad6594fe442c8ff5cd9c8137298582c1731d713bf"
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

	paste           bool
	padding         uint32
	qrRecovery      qrcode.RecoveryLevel
	ignoreSizeLimit bool

	base64 bool
	// symmetricOnly will use a built in ECDSA certificate so the user only
	// needs a password to decrypt the data
	symmetricOnly bool
}

func defaultOptions() *options {
	return &options{
		hash:  qrsecrets.HashSHA256,
		curve: elliptic.P521(),

		argonMemory:      32 * 1024,
		argonIterations:  4,
		argonParallelism: 4,
		argonKeyLen:      32,

		qrRecovery: qrcode.Medium,
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

func defaultKey() *ecdsa.PrivateKey {
	d, err := hex.DecodeString(defaultKeyD)
	if err != nil {
		panic(err)
	}

	x, err := hex.DecodeString(defaultKeyX)
	if err != nil {
		panic(err)
	}

	y, err := hex.DecodeString(defaultKeyY)
	if err != nil {
		panic(err)
	}

	return &ecdsa.PrivateKey{
		D: big.NewInt(0).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     big.NewInt(0).SetBytes(x),
			Y:     big.NewInt(0).SetBytes(y),
		},
	}
}
