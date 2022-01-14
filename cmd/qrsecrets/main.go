package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-compile/qrsecrets"
	"github.com/skip2/go-qrcode"

	"github.com/chzyer/readline"
)

const version = "v1.0.0"

func main() {
	if err := app(); err != nil {
		fmt.Println(err)
	}
}

func app() error {
	options, parameters := parseArgs(os.Args[1:])
	if options == nil {
		return nil
	}

	if len(parameters) == 0 {
		fmt.Println("[Warning] Expected a instruction e.g. encrypt, decrypt or generate-key.")
		return nil
	}

	prompt, err := readline.New("> ")
	if err != nil {
		return err
	}

	switch strings.ToLower(parameters[0]) {
	case "generate-key", "generate_key", "generatekey", "genkey", "gen-key", "gen_key":
		return generateKey(options, prompt)
	case "encrypt":
		if len(parameters) < 2 {
			fmt.Println("[Warning] You must provide a private key as a paramater.")
			return nil
		}

		return encrypt(options, prompt, parameters[1])
	case "decrypt":
		if len(parameters) < 3 {
			fmt.Println("[Warning] You must provide your private key and input media.")
			fmt.Println(" qrsecrets decrypt ./ec-P521.pem ./btc-seed.png")
			fmt.Println(" qrsecrets decrypt ./ec-P521.pem ./btc-seed.bin")
			return nil
		}

		return decrypt(options, prompt, parameters[1], parameters[2])
	default:
		fmt.Printf("[Warning] Unknown a instruction %q.\n", parameters[0])
		return nil
	}
}

func parseArgs(args []string) (*options, []string) {
	// paramaters are non argument keyed arguments
	paramaters := []string{}

	options := defaultOptions()

	for i := range args {
		// If not keyed arg append to paramaters array
		if len(args[i]) <= 1 || args[i][0] != '-' {
			paramaters = append(paramaters, args[i])
			continue
		}

		// Split based on equal opperator and trim argument prefix
		arg := strings.SplitN(args[i][1:], "=", 2)
		if len(arg) == 2 {
			// Prepend equal opperator to indicate this is a set argument
			arg[0] = arg[0] + "="
		}

		switch strings.ToLower(arg[0]) {
		case "h", "help":
			fmt.Printf("QRsecrets - %s\n", version)
			fmt.Println()
			fmt.Println(" qrsecrets encrypt ./private.pem")
			fmt.Println(" qrsecrets -hash=sha256 encrypt ./private.pem")
			fmt.Println(" qrsecrets -hash=sha256 -png=qr.png encrypt./private.pem")
			fmt.Println(" qrsecrets -hash=sha256 -output=qr.png encrypt ./private.pem")
			fmt.Println(" qrsecrets -hash=sha256 -output=secret.bin encrypt ./private.pem")
			fmt.Println(" qrsecrets -curve=p521 generate-key")
			fmt.Println(" qrsecrets -curve=p521 -encrypt=true generate-key")
			fmt.Println(" qrsecrets -curve=p521 -output=key.pem generate-key")
			fmt.Println()
			fmt.Println("Arguments:")
			fmt.Printf("  -%-12s %s\n", "hash", "Displays the hash algorithm being used")
			fmt.Printf("  -%-12s %s\n", "hashs", "List all supported hash algorithms")
			fmt.Printf("  -%-12s %s\n", "file=", "Encrypt a file instead of a string")
			fmt.Printf("  -%-12s %s\n", "masterkey=", "Set masterkey via the cli")
			fmt.Printf("  -%-12s %s\n", "output=", "Set where to output the result; PNG or Bin file")
		case "hash":
			// Print hash and trim the prefix "Hash" from the returned string
			fmt.Printf("Hash: %s\n", options.hash.String()[4:])
		case "hash=":
			switch strings.ToLower(arg[1]) {
			case "sha256", "sha_256", "sha-256":
				options.hash = qrsecrets.HashSHA256
			case "sha512", "sha_512", "sha-512":
				options.hash = qrsecrets.HashSHA512
			case "sha3_256", "sha_3_256", "sha-3-256", "sha3-256":
				options.hash = qrsecrets.HashSHA3_256
			case "sha3_512", "sha_3_512", "sha-3-512", "sha3-512":
				options.hash = qrsecrets.HashSHA3_512
			default:
				fmt.Println("[Warning] Unknown hash. Use augment -hashes to list all supported functions.")
				return nil, nil
			}
		case "hashes":
			fmt.Println("Supported hash functions:")
			fmt.Println(" SHA256")
			fmt.Println(" SHA512")
			fmt.Println(" SHA3_256")
			fmt.Println(" SHA3_512")
		case "version":
			fmt.Printf("Version: %s\n", version)
		case "encrypt=":
			b, err := parseBool(arg[1])
			if err != nil {
				fmt.Printf("[Warning] %s.\n", err)
				return nil, nil
			}

			options.encryptKey = b
		case "output=":
			options.output = arg[1]
		case "presets":
			fmt.Println("Security presets:")
			fmt.Println(" low")
			fmt.Println(" medium")
			fmt.Println(" default")
			fmt.Println(" high")
			fmt.Println(" very-high")
			fmt.Println(" slow-secure")
		case "preset=":
			if i != 0 {
				fmt.Println("[Warning] Preset must always be the first argument.")
				return nil, nil
			}

			preset, err := preset(arg[1])
			if err != nil {
				fmt.Println("[Warning] Unknown preset, run -presets for a list of all options.")
				return nil, nil
			}

			options = preset
		case "ignore-size-limit":
			options.ignoreSizeLimit = !options.ignoreSizeLimit
			fmt.Printf("[Info] Toggled ignore size limit to %v.\n", options.ignoreSizeLimit)
		case "base64":
			options.base64 = !options.base64
			fmt.Printf("[Info] Toggled base64 to %v.\n", options.base64)
		case "curve=":
			curveID := qrsecrets.CurveToID(arg[1])
			if curveID == 0 {
				fmt.Println("[Warning] Unknown curve. Use augment -curves to list all supported elliptic curves.")
				return nil, nil
			}

			options.curve = qrsecrets.IDToCurve(curveID)
		case "curves":
			fmt.Println("Supported elliptic curves:")
			fmt.Println(" P521")
			fmt.Println(" P384")
			fmt.Println(" P256")
			fmt.Println(" P224")
		case "file=":
			stat, err := os.Stat(arg[1])
			if err != nil {
				fmt.Println("File does not exist.")
				return nil, nil
			}

			if stat.IsDir() {
				fmt.Println("File you inputted is actually a directory.")
				return nil, nil
			}

			options.file = arg[1]
		case "masterkey=", "master_key", "passphrase=":
			options.masterkey = arg[1]
		case "padding":
			fmt.Println("Padding length:")
			fmt.Printf(" %d", options.padding)
		case "padding=":
			n, err := strconv.ParseUint(arg[1], 10, 32)
			if err != nil {
				fmt.Println("[Warning] Invalid or overflowing unsigned integer.")
				return nil, nil
			}

			options.padding = uint32(n)
		case "recovery":

			level := "Unknown"
			switch options.qrRecovery {
			case qrcode.Low:
				level = "Low"
			case qrcode.Medium:
				level = "Medium"
			case qrcode.High:
				level = "High"
			case qrcode.Highest:
				level = "Highest"
			}

			fmt.Printf("Recovery Level: %s\n", level)
		case "recovery=":
			switch strings.ToLower(arg[1]) {
			case "low":
				options.qrRecovery = qrcode.Low
			case "medium":
				options.qrRecovery = qrcode.Medium
			case "high":
				options.qrRecovery = qrcode.High
			case "highest":
				options.qrRecovery = qrcode.Highest
			}
		default:
			fmt.Printf("Unknown argument -%q.\n", arg[0])
			return nil, nil
			// TODO: add argon2; iterations, memory, parallelism, key length
		}
	}

	return options, paramaters
}
