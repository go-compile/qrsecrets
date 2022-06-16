package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/chzyer/readline"
	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome"
	"github.com/go-compile/rome/p224"
	"github.com/go-compile/rome/p256"
	"github.com/go-compile/rome/p384"
	"github.com/go-compile/rome/p521"
	"github.com/pkg/errors"
)

func generateKey(options *options, prompt *readline.Instance) error {

	var (
		k   rome.PrivateKey
		err error
	)

	// Generate elliptic curve private key
	switch options.curve {
	case qrsecrets.CurveP256:
		k, err = p256.Generate()
	case qrsecrets.CurveP224:
		k, err = p224.Generate()
	case qrsecrets.CurveP384:
		k, err = p384.Generate()
	case qrsecrets.CurveP521:
		k, err = p521.Generate()
	default:
		return errors.New("unknown elliptic curve")
	}

	// Print details about key
	fmt.Printf("Curve: %s Size: %d\n", k.Public().Name(), k.Public().Size())
	fmt.Printf("Fingerprint (SHA256): %x\n", k.Public().Fingerprint(sha256.New()))

	// TODO: add randomart for fingerprint
	der, err := k.PrivateASN1()
	if err != nil {
		return err
	}

	var pemData []byte
	if options.encryptKey {
		// Ask for password to encrypt key with
		pw, err := prompt.ReadPassword(fmt.Sprintf("Encrypt private key (%s)> ", k.Public().Name()))
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

	// TODO: option to split public and private key file
	filename := fmt.Sprintf("ecdsa-%s.pem", k.Public().Name())

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

			if err := f.Close(); err != nil {
				return err
			}

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

	if err := f.Truncate(0); err != nil {
		return err
	}

	if _, err := f.Write(pemData); err != nil {
		return err
	}

	fmt.Printf("[Info] Private key written to %s\n", filename)
	return nil
}
