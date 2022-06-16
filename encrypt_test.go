package qrsecrets_test

import (
	"bytes"
	"testing"

	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome/p256"
)

func TestEncryptP256(t *testing.T) {

	msg := []byte("My secret message.")
	key := "password123SECURE"

	priv, err := p256.Generate()
	if err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()

	// === ENCRYPT
	container, err := qrsecrets.NewContainer(pub.Name(), qrsecrets.HashSHA256, msg, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Set the options
	container.MetaData.ArgonIterations = 4
	container.MetaData.ArgonMemory = 32 * 1024
	container.MetaData.ArgonParallelism = 4
	container.MetaData.ArgonKeyLen = 32

	data, err := container.Marshal(pub, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	// === DECRYPT
	container, err = qrsecrets.DecodeContainer(bytes.NewBuffer(data), priv, []byte(key))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(msg, container.CipherText.Plaintext) {
		t.Fatal("plaintext text does not match")
	}
}
