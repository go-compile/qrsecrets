package qrsecrets

import (
	"crypto/elliptic"
	"strings"
)

// CurveID represents a Elliptic or Edwards curve
type CurveID uint8

//go:generate stringer -type=CurveID
const (
	// CurveP224 is a nist curve
	CurveP224 CurveID = 1 + iota
	// CurveP256 is a nist curve
	CurveP256
	// CurveP384 is a nist curve
	CurveP384
	// CurveP521 is a nist curve
	CurveP521
)

// CurveToID converts a curve name to a CurveID
func CurveToID(name string) CurveID {
	switch strings.ToLower(name) {
	case "p-224", "p224":
		return CurveP256
	case "p-256", "p256":
		return CurveP256
	case "p-384", "p384":
		return CurveP384
	case "p-521", "p521":
		return CurveP521
	default:
		return 0
	}
}

// IDToCurve takes a curve ID and returns a elliptic curve
func IDToCurve(curve CurveID) elliptic.Curve {
	switch curve {
	case CurveP224:
		return elliptic.P224()
	case CurveP256:
		return elliptic.P256()
	case CurveP384:
		return elliptic.P384()
	case CurveP521:
		return elliptic.P521()
	default:
		return nil
	}
}
