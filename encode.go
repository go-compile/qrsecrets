package qrsecrets

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/go-compile/rome"
	"golang.org/x/crypto/argon2"
)

// Encode takes a public key to encrypt the metadata section
func (c *Container) Encode(w io.Writer, pub rome.PublicKey, masterKey []byte) error {

	curve := CurveToID(pub.Name())
	if curve == 0 {
		return ErrCurveSupport
	}

	if curve != c.Curve {
		return ErrCurveMissmatch
	}

	// Write magic number
	if _, err := w.Write(MagicNumber); err != nil {
		return err
	}

	// Format version
	if _, err := w.Write([]byte{c.version}); err != nil {
		return err
	}

	// Curve ID
	if _, err := w.Write([]byte{byte(curve)}); err != nil {
		return err
	}

	// Hash ID
	if _, err := w.Write([]byte{byte(c.HashID)}); err != nil {
		return err
	}

	if err := c.MetaData.Encode(w, c, pub); err != nil {
		return err
	}

	return c.CipherText.Encode(w, c.MetaData, masterKey)
}

// Encode will write the metadata and encrypt it with ECIES
func (c *SectionMetaData) Encode(w io.Writer, container *Container, pub rome.PublicKey) error {
	if len(c.Salt) != 32 {
		return ErrSaltInvalid
	}

	// Create new buffer to write metadata section into
	// later we will encrypt this data
	buf := bytes.NewBuffer(nil)

	// Write the salt to the buffer
	if _, err := buf.Write(c.Salt); err != nil {
		return err
	}

	memory := make([]byte, 4)
	binary.BigEndian.PutUint32(memory, c.ArgonMemory)

	if _, err := buf.Write(memory); err != nil {
		return err
	}

	iterations := make([]byte, 4)
	binary.BigEndian.PutUint32(iterations, c.ArgonIterations)

	if _, err := buf.Write(iterations); err != nil {
		return err
	}

	if _, err := buf.Write([]byte{c.ArgonParallelism}); err != nil {
		return err
	}

	keyLen := make([]byte, 4)
	binary.BigEndian.PutUint32(keyLen, c.ArgonKeyLen)

	if _, err := buf.Write(keyLen); err != nil {
		return err
	}

	padding := make([]byte, 4)
	binary.BigEndian.PutUint32(padding, c.PaddingSize)

	if _, err := buf.Write(padding); err != nil {
		return err
	}

	kdf := HashIDToKDF(container.HashID)
	if kdf == nil {
		return ErrHashUnsupported
	}

	// TODO: add cipher option for encrypt
	// TODO: implement KDF option for encrypt

	// Encrypt the metadata section using ECIES-AES256-SHA256 (or other specified hash function)
	ciphertext, err := pub.Encrypt(buf.Bytes(), rome.CipherAES_GCM, kdf)
	if err != nil {
		return err
	}

	cipherTextLen := make([]byte, 2)
	binary.BigEndian.PutUint16(cipherTextLen, uint16(len(ciphertext)))

	// Write the length of ciphertext
	if _, err := w.Write(cipherTextLen); err != nil {
		return err
	}

	// Write ciphertext to underlying writer
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// Encode encrypts and marshales the plaintext
func (c *SectionCipherText) Encode(w io.Writer, m *SectionMetaData, masterKey []byte) error {
	key := argon2.Key(masterKey, m.Salt, m.ArgonIterations, m.ArgonMemory, m.ArgonParallelism, m.ArgonKeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	aesgcm, err := cipher.NewGCM(block)

	if err != nil {
		return err
	}

	// Append padding to the end of ciphertext and encrypt
	ciphertext := aesgcm.Seal(nil, nonce, append(c.Plaintext, c.Padding...), nil)
	ciphertext = append(nonce, ciphertext...)

	cipherTextLen := make([]byte, 8)
	binary.BigEndian.PutUint64(cipherTextLen, uint64(len(ciphertext)))

	// Write the length of ciphertext
	if _, err := w.Write(cipherTextLen); err != nil {
		return err
	}

	// Write ciphertext to underlying writer
	if _, err := w.Write(ciphertext); err != nil {
		return err
	}

	return nil
}

// Marshal encodes the container and returns it in bytes
func (c *Container) Marshal(pub rome.PublicKey, masterKey []byte) (data []byte, err error) {
	buf := bytes.NewBuffer(nil)

	err = c.Encode(buf, pub, masterKey)
	data = buf.Bytes()

	return data, err
}
