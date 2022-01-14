package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/1william1/ecc"
	"github.com/chzyer/readline"
	"github.com/go-compile/qrsecrets"
	"github.com/liyue201/goqr"

	_ "image/jpeg"
	_ "image/png"
)

func decrypt(options *options, prompt *readline.Instance, privateKeyFile string, inputFile string) error {

	priv, err := readPrivateKey(privateKeyFile, prompt)
	if err != nil {
		return err
	}

	// Convert ECDSA private key to ECC private key
	key := &ecc.Private{
		D: priv.D,
		Public: &ecc.Public{
			Curve: priv.Curve,
			X:     priv.X,
			Y:     priv.Y,
		},
	}

	fmt.Printf("[Info] Opening %s\n", inputFile)

	f, err := os.OpenFile(inputFile, os.O_RDONLY, os.ModeExclusive)
	if err != nil {
		return err
	}

	defer f.Close()

	content := []byte{}
	switch strings.ToLower(filepath.Ext(inputFile)) {
	case ".png", ".jpg", "jpeg":
		content, err = decodeQRcode(f)
		if err != nil {
			return err
		}

		fmt.Printf("[Info] Scanned QR code and obtained %d bytes\n", len(content))
	default:
		content, err = ioutil.ReadAll(f)
		if err != nil {
			return err
		}

		fmt.Printf("[Info] Opened file and read %d bytes\n", len(content))
	}

	if options.base64 {
		content, err = base64.RawStdEncoding.DecodeString(string(content))
		if err != nil {
			return err
		}

		fmt.Printf("[Info] Base64 decode %d bytes\n", len(content))
	}

	// If master key has been set via the CLI don't ask for it again
	masterKey := []byte(options.masterkey)
	if options.masterkey == "" {
		fmt.Println("Input your master key:")
		masterKey, err = prompt.ReadPassword("Master key: ")
		if err != nil {
			return err
		}
	}

	container, err := qrsecrets.UnmarshalContainer(content, key, masterKey)
	if err != nil {
		return err
	}

	// TODO: write plaintext to -output= arg file location if set
	fmt.Printf("[Info] Success, decrypted %d bytes:\n", len(container.CipherText.Plaintext))
	fmt.Println(string(container.CipherText.Plaintext))

	return nil
}

func decodeQRcode(f io.Reader) ([]byte, error) {
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}

	codes, err := goqr.Recognize(img)
	if err != nil {
		return nil, err
	}

	if len(codes) < 1 {
		return nil, errors.New("no qr code found in image")
	}

	return codes[0].Payload, nil
}
