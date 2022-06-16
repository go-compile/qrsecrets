package main

import (
	"strings"

	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome"
	"github.com/skip2/go-qrcode"

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
	curve qrsecrets.CurveID
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
		curve: qrsecrets.CurveP521,

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

func defaultKey() rome.PrivateKey {
	// nist P521 Elliptic Curve

	// it is recommended to specify your own key instead of using the default
	// for symmetric mode
	k, err := rome.ParseECPrivate([]byte(`-----BEGIN EC PRIVATE KEY-----
	MIHcAgEBBEIB9mBasFi26aQ1iIPXHkjs4iWpYF9zBQI7wFTa6s0YY5+3WNXoVTlY
	ZH9ynDRGqmDbE8GlLTbC4gYtrJM+bYUx1hygBwYFK4EEACOhgYkDgYYABACHY/il
	Hhr0VA4OmzTA89Iwv+xhY+oZdLkvlFGuAxDdh2vE3uBC+Gv77MZcGbnd6+db/BTS
	+Y+DKhD4i/O0xuVkBgDCYOsHhCXrJ1f5dHSsd08CisGh2Cvp1ERhd+yyEIZU29lz
	wLGpx27D0h4n19iRSsWUNFL30CjdwZp4W2nOfzlstQ==
	-----END EC PRIVATE KEY-----`))
	if err != nil {
		panic(err)
	}

	return k
}
