package qrsecrets

import (
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

	// Brain pool curves
	CurveP160t1
	CurveP192r1
	CurveP192t1
	CurveP224r1
	CurveP224t1
	CurveP256r1
	CurveP256t1
	CurveP320r1
	CurveP320t1
	CurveP384r1
	CurveP384t1
	CurveP512r1
	CurveP512t1
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
	case "p-160t1", "p160t1":
		return CurveP160t1
	case "p-192r1", "p192r1":
		return CurveP192r1
	case "p-192t1", "p192t1":
		return CurveP192t1
	case "p-224r1", "p224r1":
		return CurveP224r1
	case "p-224t1", "p224t1":
		return CurveP224t1
	case "p-256r1", "p256r1":
		return CurveP256r1
	case "p-256t1", "p256t1":
		return CurveP256t1
	case "p-320r1", "p320r1":
		return CurveP320r1
	case "p-320t1", "p320t1":
		return CurveP320t1
	case "p-384r1", "p384r1":
		return CurveP384r1
	case "p-384t1", "p384t1":
		return CurveP384t1
	case "p-512r1", "p512r1":
		return CurveP512r1
	case "p-512t1", "p512t1":
		return CurveP512t1
	default:
		return 0
	}
}
