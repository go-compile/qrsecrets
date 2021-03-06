package main

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"image/jpeg"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
	"github.com/go-compile/qrsecrets"
	"github.com/go-compile/rome"
	"github.com/go-compile/rome/parse"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
)

func encrypt(options *options, prompt *readline.Instance, keyFile string) error {

	var (
		priv rome.PrivateKey
		pub  rome.PublicKey
		err  error
	)

	if options.symmetricOnly {
		// Set default key if using symmetric only
		// user is warned this is insecure when enabling the option.
		priv = defaultKey()
	} else {
		priv, pub, err = readKey(keyFile, prompt)
		if err != nil {
			return err
		}

		// extract public key from private
		if priv != nil {
			pub = priv.Public()
		}
	}

	content := []byte{}

	if options.file != "" {
		content, err = ioutil.ReadFile(options.file)
		if err != nil {
			return err
		}

		fmt.Printf("[Info] File %q's contents is being used as the plain text.\n", options.file)
	} else {
		fmt.Println("Input your data you want to protect:")
		plaintext, err := prompt.Readline()
		if err != nil {
			return err
		}

		content = []byte(plaintext)
	}

	if !options.ignoreSizeLimit && len(content) >= 2953 {
		fmt.Println("QR code can only fit 2953 bytes, run with arg -ignore-size-limit to ignore limit at your own caution")
		return nil
	} else if options.base64 && base64.RawStdEncoding.EncodedLen(len(content)) >= 2953 {
		fmt.Printf("QR code can only fit %d bytes when using base64, run with arg -ignore-size-limit to ignore limit at your own caution\n", 2953/4)
		return nil
	}

	// Create new container for secret
	container, err := qrsecrets.NewContainer(pub.Name(), options.hash, content, int32(options.padding))
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

	data, err := container.Marshal(pub, masterKey)
	if err != nil {
		return err
	}

	// If no file is specified print to terminal
	if options.output == "" {
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

	if options.base64 {
		data = []byte(base64.RawStdEncoding.EncodeToString(data))
	}

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

// read key will take a key input and return either a public or private key based on the file.
// Note: a private key will not fill out the public key
func readKey(file string, prompt *readline.Instance) (rome.PrivateKey, rome.PublicKey, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, nil, err
	}

	pemBlock, rest := pem.Decode(content)
	if len(rest) > 0 {
		return nil, nil, errors.New("didn't decode all of PEM file")
	}

	if x509.IsEncryptedPEMBlock(pemBlock) {

		pw, err := prompt.ReadPassword(fmt.Sprintf("Passphrase for (%s): ", file))
		if err != nil {
			return nil, nil, err
		}

		pemData, err := x509.DecryptPEMBlock(pemBlock, pw)
		if err != nil {
			return nil, nil, err
		}

		pemBlock.Bytes = pemData
	}

	switch pemBlock.Type {
	case "EC PRIVATE KEY":
		key, err := parse.PrivateASN1(pemBlock.Bytes)
		return key, nil, err
	case "EC PUBLIC KEY":
		key, err := parse.PublicASN1(pemBlock.Bytes)
		return nil, key, err
	case "RSA PRIVATE KEY":
		return nil, nil, errors.New("RSA is not supported")
	default:
		return nil, nil, errors.New(fmt.Sprintf("unsupported private key type %q", pemBlock.Type))
	}
}
