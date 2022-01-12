package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/1william1/ecc"
	"github.com/chzyer/readline"
)

func generateKey(options *options, prompt *readline.Instance) error {

	// Generate elliptic curve private key
	priv, err := ecc.GenerateKey(options.curve)
	if err != nil {
		return err
	}

	// Print details about key
	fmt.Printf("Curve: %s Bitsize: %d\n", priv.Public.Curve.Params().Name, priv.Public.Curve.Params().BitSize)
	fmt.Printf("Fingerprint (SHA256): %x\n", priv.Public.Fingerprint())

	// TODO: add randomart for fingerprint
	der, err := x509.MarshalECPrivateKey(priv.ToECDSA())
	if err != nil {
		return err
	}

	var pemData []byte
	if options.encryptKey {
		// Ask for password to encrypt key with
		pw, err := prompt.ReadPassword(fmt.Sprintf("Encrypt private key (%s)> ", priv.Public.Curve.Params().Name))
		if err != nil {
			return err
		}

		// Encrypt pem block
		keyPem, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, pw, x509.PEMCipherAES256)
		if err != nil {
			return err
		}

		// Encode from struct to pem block
		pemData = pem.EncodeToMemory(keyPem)
	} else {
		// Encode from struct to pem block with no protection
		pemData = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: der,
		})
	}

	// Write to default file
	if options.output == "" {
		// TODO: check if file exists and ask if to overwrite
		return ioutil.WriteFile("ec.pem", pemData, os.ModeExclusive)
	}

	return ioutil.WriteFile(options.output, pemData, os.ModeExclusive)
}
