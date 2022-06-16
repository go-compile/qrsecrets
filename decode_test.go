package qrsecrets_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome/p256"
)

func TestDecode(t *testing.T) {
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

	co, err := qrsecrets.DecodeContainer(buf, private, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	if co.HashID != hash {
		t.Fatal("new container hash does not match input option")
	}

	if co.Curve != qrsecrets.CurveP256 {
		t.Fatal("new container curve does not match input option")
	}

	if len(co.MetaData.Salt) != 32 {
		t.Fatal("salt is not 32 bytes long")
	}

	if !bytes.Equal(co.MetaData.Salt, c.MetaData.Salt) {
		t.Fatal("salt does not match")
	}

	if co.MetaData.ArgonIterations != c.MetaData.ArgonIterations {
		t.Fatal("argon2 iterations does not match")
	}

	if co.MetaData.ArgonKeyLen != c.MetaData.ArgonKeyLen {
		t.Fatal("argon2 key len does not match")
	}

	if co.MetaData.ArgonMemory != c.MetaData.ArgonMemory {
		t.Fatal("argon2 memory does not match")
	}

	if co.MetaData.ArgonParallelism != c.MetaData.ArgonParallelism {
		t.Fatal("argon2 parallelism does not match")
	}

	if co.MetaData.PaddingSize != c.MetaData.PaddingSize {
		t.Fatal("argon2 padding size does not match")
	}

	if string(co.CipherText.Plaintext) != secret {
		t.Fatalf("plaintext does not match. got: %q wanted %q", co.CipherText.Plaintext, secret)
	}

	if len(co.CipherText.Padding) != 64-len(secret) {
		t.Fatalf("padding does not match. Expected len to be %d, got %d", 64-len(secret), len(co.CipherText.Padding))
	}
}
