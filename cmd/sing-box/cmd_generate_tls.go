package main

import (
	"io"
	"os"
	"time"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/spf13/cobra"
)

var (
	flagGenerateTLSKeyPairMonths int
	flagGenerateTLSKeyPairEcc    bool
)

var commandGenerateTLSKeyPair = &cobra.Command{
	Use:   "tls-keypair <server_name>",
	Short: "Generate TLS self sign key pair",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := generateTLSKeyPair(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerateTLSKeyPair.Flags().IntVarP(&flagGenerateTLSKeyPairMonths, "months", "m", 1, "Valid months")
	commandGenerateTLSKeyPair.Flags().BoolVarP(&flagGenerateTLSKeyPairEcc, "ecc", "e", false, "Use ECDSA instead of RSA")
	commandGenerate.AddCommand(commandGenerateTLSKeyPair)

	commandGenerate.AddCommand(commandGeneratePemHash)
}

func generateTLSKeyPair(serverName string) (err error) {
	var privateKeyPem, publicKeyPem []byte
	expire := time.Now().AddDate(0, flagGenerateTLSKeyPairMonths, 0)
	if flagGenerateTLSKeyPairEcc {
		privateKeyPem, publicKeyPem, err = tls.GenerateCertificateECC(nil, nil, time.Now, serverName, expire)
	} else {
		privateKeyPem, publicKeyPem, err = tls.GenerateCertificate(nil, nil, time.Now, serverName, expire)
	}
	if err != nil {
		return
	}
	os.Stdout.WriteString(string(privateKeyPem) + "\n")
	os.Stdout.WriteString(string(publicKeyPem) + "\n")
	return
}

var commandGeneratePemHash = &cobra.Command{
	Use:   "pem-hash <file>",
	Short: "Generate V2Ray style cert chain hash",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := generatePemHash(args[0])
		if err != nil {
			log.Fatal(err)
		}
	},
}

func generatePemHash(input string) error {
	var reader io.Reader
	switch input {
	case "-", "stdin":
		reader = os.Stdin
	default:
		file, err := os.Open(input)
		if err != nil {
			return E.Cause(err, "open cert file")
		}
		defer file.Close()
		reader = file
	}
	content, err := io.ReadAll(reader)
	if err != nil {
		return E.Cause(err, "read cert content")
	}
	hash := tls.CalculatePEMCertHash(content)
	os.Stdout.WriteString(string(hash) + "\n")
	return nil
}
