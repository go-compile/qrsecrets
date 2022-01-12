package qrsecrets

import (
	"crypto/elliptic"
	"crypto/rand"

	"github.com/pkg/errors"
)

// Container is used to hold the metadata and ciphertext section together and communicate some
// configuration and protocol version information to the decoder
type Container struct {
	// Magic number will be inserted on encode

	// version is the protocol version
	version uint8
	// Curve specifies which curve to use for the ECIES on the metadata section
	Curve CurveID
	// HashID is used with HKDF on the metadata section
	HashID HashID

	MetaData   *SectionMetaData
	CipherText *SectionCipherText
}

// SectionMetaData is used to store configuration data on how to decrypt the ciphertext section
type SectionMetaData struct {
	// Salt is 32 bytes long
	Salt             []byte
	ArgonMemory      uint32
	ArgonIterations  uint32
	ArgonParallelism uint8
	ArgonKeyLen      uint32
	PaddingSize      uint32
}

// SectionCipherText is used to store the secret content
type SectionCipherText struct {
	Plaintext []byte
	Padding   []byte
}

// ProtocolVersion specifies the default version of the protocol
const ProtocolVersion uint8 = 1

var (
	// MagicNumber is prepended to the container to identify its format
	MagicNumber = []byte{95, 219, 76}

	// ErrSaltInvalid is returned when a salt is the wrong length
	ErrSaltInvalid = errors.New("invalid salt must be 32 bytes long")
	// ErrCurveSupport is returned when a curve is not supported for ECIES
	ErrCurveSupport = errors.New("curve is not supported")
	// ErrCurveMissmatch is returned if you have a different container curve ID to the public key's curve ID
	ErrCurveMissmatch = errors.New("curve of public key does not match curve of container")
	// ErrHashUnsupported is returned when trying to obtain a HKDF with a hash which isn't supported
	ErrHashUnsupported = errors.New("hash is unsupported")
)

// NewContainer will create a new container to store the secret content
func NewContainer(curve elliptic.Curve, hash HashID, plaintext []byte, padding int32) (*Container, error) {

	c := &Container{
		version: ProtocolVersion,
		Curve:   CurveToID(curve.Params().Name),
		HashID:  hash,

		MetaData: &SectionMetaData{
			Salt:             make([]byte, 32),
			ArgonMemory:      32 * 1024,
			ArgonIterations:  3,
			ArgonParallelism: 4,
			ArgonKeyLen:      32,

			PaddingSize: uint32(padding),
		},

		CipherText: &SectionCipherText{
			Plaintext: plaintext,
			Padding:   make([]byte, padding),
		},
	}

	// Generate the salt
	n, err := rand.Read(c.MetaData.Salt)
	if err != nil {
		return nil, err
	} else if n != 32 {
		return nil, ErrSaltInvalid
	}

	return c, nil
}
