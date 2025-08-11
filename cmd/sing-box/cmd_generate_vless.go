package main

import (
	"os"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-vmess/vless/encryption"

	"github.com/spf13/cobra"
)

func init() {
	commandGenerate.AddCommand(commandGenerateVLESSKeypair)
}

var commandGenerateVLESSKeypair = &cobra.Command{
	Use:   "vless-mlkem768",
	Short: "Generate VLESS mlkem768 key",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var seed string
		if len(args) > 0 {
			seed = args[0]
		}
		err := generateVLESSMlkem768(seed)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func generateVLESSMlkem768(seed string) error {
	seedBase64, clientBase64, err := encryption.GenMLKEM768(seed)
	if err != nil {
		return err
	}
	os.Stdout.WriteString("Seed: " + seedBase64 + "\n")
	os.Stdout.WriteString("Client: " + clientBase64 + "\n")
	return nil
}
