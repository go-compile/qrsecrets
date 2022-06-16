package qrsecrets_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome/p256"
)

func TestNewContainer(t *testing.T) {

	secret := "Hello this is my secret"
	hash := qrsecrets.HashSHA256

	private, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	c, err := qrsecrets.NewContainer(private.Public().Name(), hash, []byte(secret), 64-int32(len(secret)))
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
	key := "Password123"

	private, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	c, err := qrsecrets.NewContainer(private.Public().Name(), hash, []byte(secret), 64-int32(len(secret)))
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	if err := c.Encode(buf, private.Public(), []byte(key)); err != nil {
		t.Fatal(err)
	}

}
