package qrsecrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"

	"github.com/1william1/ecc"
	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

var (
	// ErrNotContainer is returned if the content trying to be decoded is not
	// a container
	ErrNotContainer = errors.New("stream is not a container")
	// ErrProtocolVersionSupport is returned if the version of the protocol
	// in the container is not a supported version and can not be decoded
	ErrProtocolVersionSupport = errors.New("protocol version is not supported")

	ErrCipherTextShort = errors.New("ciphertext is too short to be valid")
)

// DecodeContainer will decode a container and decrypt it
func DecodeContainer(r io.Reader, priv *ecc.Private, masterKey []byte) (*Container, error) {

	// Read magic number
	magicNum := make([]byte, 3)
	if _, err := io.ReadFull(r, magicNum); err != nil {
		return nil, err
	}

	if !bytes.Equal(magicNum, magicNum) {
		return nil, ErrNotContainer
	}

	version := make([]byte, 1)
	if _, err := io.ReadFull(r, version); err != nil {
		return nil, err
	}

	// Check if this is the right protocol version
	// If we add new protocol versions this needs to be turned into a
	// switch statement pointing to different decode functions for different
	// versions
	if version[0] != ProtocolVersion {
		return nil, ErrProtocolVersionSupport
	}

	curve := make([]byte, 1)
	if _, err := io.ReadFull(r, curve); err != nil {
		return nil, err
	}

	hash := make([]byte, 1)
	if _, err := io.ReadFull(r, hash); err != nil {
		return nil, err
	}

	c := &Container{
		version: version[0],
		Curve:   CurveID(curve[0]),
		HashID:  HashID(hash[0]),
	}

	metadata, err := decodeMetaDataSection(r, c, priv)
	if err != nil {
		return nil, err
	}

	c.MetaData = metadata

	ciphertext, err := decodeCiphertextSection(r, metadata, masterKey)
	if err != nil {
		return nil, err
	}

	c.CipherText = ciphertext

	return c, nil
}

func decodeMetaDataSection(r io.Reader, c *Container, priv *ecc.Private) (*SectionMetaData, error) {

	cipherTextLen := make([]byte, 2)
	if _, err := io.ReadFull(r, cipherTextLen); err != nil {
		return nil, err
	}

	cipherText := make([]byte, binary.BigEndian.Uint16(cipherTextLen))
	if _, err := io.ReadFull(r, cipherText); err != nil {
		return nil, err
	}

	curve := IDToCurve(c.Curve)
	if curve == nil {
		return nil, ErrCurveSupport
	}

	hkdf := HashIDToKDF(c.HashID)
	if hkdf == nil {
		return nil, ErrHashUnsupported
	}

	// decrypt the metadata section by using the private key and the peramaters in the container
	plaintext, err := priv.Decrypt(cipherText, curve, &ecc.EncryptOption{Property: ecc.PropertyKDF, Value: hkdf})
	if err != nil {
		return nil, err
	}

	// create a new buffer of the plain text to read from
	buf := bytes.NewBuffer(plaintext)

	m := &SectionMetaData{}

	// Get the salt from the newly created buffer
	salt := make([]byte, 32)
	if _, err := io.ReadFull(buf, salt); err != nil {
		return nil, err
	}

	m.Salt = salt

	memory := make([]byte, 4)
	if _, err := io.ReadFull(buf, memory); err != nil {
		return nil, err
	}

	m.ArgonMemory = binary.BigEndian.Uint32(memory)

	iterations := make([]byte, 4)
	if _, err := io.ReadFull(buf, iterations); err != nil {
		return nil, err
	}

	m.ArgonIterations = binary.BigEndian.Uint32(iterations)

	parallelism := make([]byte, 1)
	if _, err := io.ReadFull(buf, parallelism); err != nil {
		return nil, err
	}

	m.ArgonParallelism = parallelism[0]

	keyLen := make([]byte, 4)
	if _, err := io.ReadFull(buf, keyLen); err != nil {
		return nil, err
	}

	m.ArgonKeyLen = binary.BigEndian.Uint32(keyLen)

	padding := make([]byte, 4)
	if _, err := io.ReadFull(buf, padding); err != nil {
		return nil, err
	}

	m.PaddingSize = binary.BigEndian.Uint32(padding)

	return m, nil
}

func decodeCiphertextSection(r io.Reader, m *SectionMetaData, masterKey []byte) (*SectionCipherText, error) {
	// Get len of ciphertext
	cipherTextLen := make([]byte, 8)
	if _, err := io.ReadFull(r, cipherTextLen); err != nil {
		return nil, err
	}

	// Check if ciphertext is long enough to fit the nonce
	if binary.BigEndian.Uint64(cipherTextLen) <= 12 {
		return nil, ErrCipherTextShort
	}

	// Read the nonce which is prepended to the ciphertext
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}

	// Read the rest of the ciphertext
	cipherText := make([]byte, binary.BigEndian.Uint64(cipherTextLen)-12)
	if _, err := io.ReadFull(r, cipherText); err != nil {
		return nil, err
	}

	// Derive the key with Argon2 again
	key := argon2.Key(masterKey, m.Salt, m.ArgonIterations, m.ArgonMemory, m.ArgonParallelism, m.ArgonKeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}

	// Make sure the padding params are valid
	if len(plaintext) < int(m.PaddingSize) {
		return nil, ErrCipherTextShort
	}

	c := &SectionCipherText{
		Plaintext: plaintext[:len(plaintext)-int(m.PaddingSize)],
		Padding:   plaintext[len(plaintext)-int(m.PaddingSize):],
	}

	return c, nil
}
