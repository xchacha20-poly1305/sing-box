package main

import (
	"os"

	"github.com/sagernet/sing-box/log"

	"filippo.io/age"
	"github.com/spf13/cobra"
)

var (
	flagGenerateAgeHybrid bool
)

var commandGenerateAge = &cobra.Command{
	Use:   "age",
	Short: "Generate an age identity",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		err := generateAgeIdentity()
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	commandGenerateAge.Flags().BoolVarP(&flagGenerateAgeHybrid, "pq", "p", false, "Use post-quantum hybrid")
	commandGenerate.AddCommand(commandGenerateAge)
}

func generateAgeIdentity() error {
	var identityString, recipientString string
	if flagGenerateAgeHybrid {
		identity, err := age.GenerateHybridIdentity()
		if err != nil {
			return err
		}
		identityString = identity.String()
		recipientString = identity.Recipient().String()
	} else {
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		identityString = identity.String()
		recipientString = identity.Recipient().String()
	}
	_, _ = os.Stdout.WriteString("Identity: " + identityString + "\n")
	_, _ = os.Stdout.WriteString("Recipient: " + recipientString + "\n")
	return nil
}
