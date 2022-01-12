package qrsecrets_test

import (
	"bytes"
	"crypto/elliptic"
	"qrsecrets"
	"testing"

	"github.com/1william1/ecc"
)

func TestNewContainer(t *testing.T) {

	secret := "Hello this is my secret"
	hash := qrsecrets.HashSHA256
	curve := elliptic.P256()

	c, err := qrsecrets.NewContainer(curve, hash, []byte(secret), 64-int32(len(secret)))
	if err != nil {
		t.Fatal(err)
	}

	if c.HashID != hash {
		t.Fatal("new container hash does not match input option")
	}

	if c.Curve != qrsecrets.CurveP256 {
		t.Fatal("new container curve does not match input option")
	}

	if len(c.MetaData.Salt) != 32 {
		t.Fatal("salt is not 32 bytes long")
	}

	if bytes.Equal(c.MetaData.Salt, make([]byte, 32)) {
		t.Fatal("salt is a empty 32 byte slice")
	}

	if !bytes.Equal(c.CipherText.Plaintext, []byte(secret)) {
		t.Fatal("plain text does not match input")
	}

	if len(c.CipherText.Padding) != 64-len(secret) {
		t.Fatal("salt is not 32 bytes long")
	}
}

func TestEncode(t *testing.T) {
	secret := "Hello this is my secret"
	hash := qrsecrets.HashSHA256
	curve := elliptic.P256()
	key := "Password123"

	c, err := qrsecrets.NewContainer(curve, hash, []byte(secret), 64-int32(len(secret)))
	if err != nil {
		t.Fatal(err)
	}

	private, err := ecc.GenerateKey(curve)
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	if err := c.Encode(buf, private.Public, []byte(key)); err != nil {
		t.Fatal(err)
	}

}
