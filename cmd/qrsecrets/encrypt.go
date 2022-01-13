package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"image/jpeg"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/1william1/ecc"
	"github.com/chzyer/readline"
	"github.com/go-compile/qrsecrets"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
)

func encrypt(options *options, prompt *readline.Instance, privateKeyFile string) error {

	priv, err := readPrivateKey(privateKeyFile, prompt)
	if err != nil {
		return err
	}

	// Convert ECDSA private key to ECC private key
	key := ecc.Private{
		D: priv.D,
		Public: &ecc.Public{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
	}

	// TODO: Check if -file= arg is set
	fmt.Println("Input your data you want to protect:")
	plaintext, err := prompt.Readline()
	if err != nil {
		return err
	}

	// Create new container for secret
	container, err := qrsecrets.NewContainer(key.Public.Curve, options.hash, []byte(plaintext), int32(options.padding))
	if err != nil {
		return err
	}

	// Set the options
	container.MetaData.ArgonIterations = options.argonIterations
	container.MetaData.ArgonMemory = options.argonMemory
	container.MetaData.ArgonParallelism = options.argonParallelism
	container.MetaData.ArgonKeyLen = options.argonKeyLen

	// If master key has been set via the CLI don't ask for it again
	masterKey := []byte(options.masterkey)
	if options.masterkey == "" {
		fmt.Println("Input your master key:")
		masterKey, err = prompt.ReadPassword(" Master key> ")
		if err != nil {
			return err
		}
	}

	data, err := container.Marshal(key.Public, masterKey)
	if err != nil {
		return err
	}

	// If no file is specified print to terminal
	if options.output == "" {
		// TODO: make qrcode recovery level a option
		qr, err := qrcode.New(string(data), options.qrRecovery)
		if err != nil {
			return err
		}

		fmt.Println(qr.ToSmallString(false))
		return nil
	}

	w, err := os.OpenFile(options.output, os.O_WRONLY, os.ModeExclusive)
	if err == nil {
		// File exists, ask if we want to overwrite it
		fmt.Printf("File %q already exits, do you want to overwrite it?", options.output)
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

		// Truncate file so we have a empty file to work with bellow
		if err := w.Truncate(0); err != nil {
			return err
		}

	} else {
		// If file doesn't exist create it and set w as the new writer
		if os.IsNotExist(err) {
			w, err = os.Create(options.output)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	}

	defer w.Close()

	imageSize := len(data)
	switch strings.ToLower(filepath.Ext(options.output)) {
	case ".png":
		qr, err := qrcode.New(string(data), options.qrRecovery)
		if err != nil {
			return err
		}

		if err := qr.Write(imageSize, w); err != nil {
			return err
		}

		fmt.Printf("[Info] Success, png has been saved to %q.\n", options.output)
		return nil
	case ".jpg", "jpeg":
		qr, err := qrcode.New(string(data), options.qrRecovery)
		if err != nil {
			return err
		}

		if err := jpeg.Encode(w, qr.Image(imageSize), &jpeg.Options{Quality: jpeg.DefaultQuality}); err != nil {
			return err
		}

		fmt.Printf("[Info] Success, jpeg has been saved to %q.\n", options.output)
		return nil
	default:
		// Write raw bytes to file instead of encoding with a qr code
		if _, err := w.Write(data); err != nil {
			return err
		}

		fmt.Printf("[Info] Success, binary file has been saved to %q.\n", options.output)
		return nil
	}
}

func readPrivateKey(file string, prompt *readline.Instance) (*ecdsa.PrivateKey, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	pemBlock, rest := pem.Decode(content)
	if len(rest) > 0 {
		return nil, errors.New("didn't decode all of PEM file")
	}

	if x509.IsEncryptedPEMBlock(pemBlock) {

		pw, err := prompt.ReadPassword(fmt.Sprintf("Passphrase for (%s): ", file))
		if err != nil {
			return nil, err
		}

		pemData, err := x509.DecryptPEMBlock(pemBlock, pw)
		if err != nil {
			return nil, err
		}

		pemBlock.Bytes = pemData
	}

	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	case "RSA PRIVATE KEY":
		return nil, errors.New("RSA is not supported")
	default:
		return nil, errors.New(fmt.Sprintf("unsupported private key type %q", pemBlock.Type))
	}
}
