package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/1william1/ecc"
	"github.com/chzyer/readline"
	"github.com/pkg/errors"
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

	filename := fmt.Sprintf("ecdsa-%s.pem", priv.Public.Curve.Params().Name)

	// If output file has been set use that instead
	if options.output != "" {
		filename = options.output
	}

	f, err := os.OpenFile(filename, os.O_WRONLY, os.ModeExclusive)
	if err != nil {
		if os.IsNotExist(err) {

			f, err := os.Create(filename)
			if err != nil {
				return err
			}

			if _, err := f.Write(pemData); err != nil {
				return err
			}

			f.Close()

			fmt.Printf("[Info] Private key written to %s\n", filename)

			return nil
		}

		return errors.Wrap(err, "opening file")
	}

	defer f.Close()

	fmt.Println("File already exits, do you want to overwrite it?")
	prompt.SetPrompt("Overwrite (y/n): ")
	overwrite, err := prompt.ReadlineWithDefault("n")
	if err != nil {
		return err
	}

	ow, err := parseBool(overwrite)
	if err != nil {
		return err
	}

	if !ow {
		fmt.Println("[Info] Aborting, file was not overwritten")
		return nil
	}

	if _, err := f.Write(pemData); err != nil {
		return err
	}

	fmt.Printf("[Info] Private key written to %s\n", filename)
	return nil

}
