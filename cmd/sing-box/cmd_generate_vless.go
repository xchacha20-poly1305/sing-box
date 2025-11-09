package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-vmess/vless/encryption"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var (
	flagGenerateVlessMlkem768 bool
)

var commandGenerateVlessEncryption = &cobra.Command{
	Use:   "vless-enc",
	Short: "Generate VLESS encryption",
	Long:  "Generate ready to use VLESS encryption/decryption.",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var privateKey string
		if len(args) > 0 {
			arg0 := args[0]
			switch arg0 {
			case "-", "stdin":
				stdin, err := io.ReadAll(os.Stdin)
				if err != nil {
					log.Fatal(err)
				}
				privateKey = string(stdin)
			default:
				privateKey = arg0
			}
		}
		err := generateVlessEncryption(privateKey)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerateVlessEncryption.Flags().BoolVarP(&flagGenerateVlessMlkem768, "mlkem", "m", false, "Use post-quantum ML-KEM-768")
	commandGenerate.AddCommand(commandGenerateVlessEncryption)
}

func generateVlessEncryption(privateKey string) (err error) {
	var serverKey, clientKey string
	if flagGenerateVlessMlkem768 {
		serverKey, clientKey, err = generateVlessMlkem768([]byte(privateKey))
	} else {
		serverKey, clientKey, err = generateVlessX25519([]byte(privateKey))
	}
	if err != nil {
		return
	}
	_, _ = os.Stdout.WriteString("decryption: " + generateDotConfig("600s", serverKey) + "\n")
	_, _ = os.Stdout.WriteString("encryption: " + generateDotConfig("0rtt", clientKey) + "\n")
	return
}

func generateVlessX25519(privateKey []byte) (serverKey, clientKey string, err error) {
	switch len(privateKey) {
	case 0:
		privateKey = make([]byte, encryption.X25519KeySize)
		rand.Read(privateKey)
	case encryption.X25519KeySize:
	default:
		err = E.New("invalid length of X25519 private key: ", string(privateKey))
		return
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html
	// (Just to make sure printing the real private key)
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	x25519PrivateKey, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		return
	}
	publicKey := x25519PrivateKey.PublicKey().Bytes()
	serverKey = base64.RawURLEncoding.EncodeToString(privateKey)
	clientKey = base64.RawURLEncoding.EncodeToString(publicKey)
	return
}

func generateVlessMlkem768(seed []byte) (serverKey, clientKey string, err error) {
	switch len(seed) {
	case 0:
		seed = make([]byte, mlkem.SeedSize)
		rand.Read(seed)
	case mlkem.SeedSize:
	default:
		err = E.New("invalid length of ML-KEM-768 seed: ", string(seed))
		return
	}

	decapsulationKey, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		return
	}
	serverKey = base64.RawURLEncoding.EncodeToString(seed)
	clientKey = base64.RawURLEncoding.EncodeToString(decapsulationKey.EncapsulationKey().Bytes())
	return
}

func generateDotConfig(time, key string) string {
	return "mlkem768x25519plus" + "." + "native" + "." + time + "." + key
}
