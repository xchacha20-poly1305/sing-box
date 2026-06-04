package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"

	"filippo.io/age"
	"filippo.io/age/armor"
	"github.com/spf13/cobra"
)

var commandAge = &cobra.Command{
	Use:   "age",
	Short: "age utils",
}

func init() {
	commandAge.AddCommand(commandAgeCovert)
	commandAge.AddCommand(commandAgeDecrypt)
	commandAge.AddCommand(commandAgeEncrypt)

	mainCommand.AddCommand(commandAge)
}

var commandAgeCovert = &cobra.Command{
	Use:   "convert",
	Short: "Convert age identity to recipient",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		var inputName string
		if len(args) >= 1 {
			inputName = args[0]
		}
		reader, err := parseReader(inputName)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Fatal(err)
			}
			reader = io.NopCloser(strings.NewReader(inputName))
		}
		defer reader.Close()
		err = ageConvertIdentityToRecipient(reader)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func ageConvertIdentityToRecipient(reader io.Reader) error {
	identities, err := age.ParseIdentities(reader)
	if err != nil {
		return E.Cause(err, "parse age identities")
	}
	for _, identity := range identities {
		var recipient string
		switch identity := identity.(type) {
		case *age.X25519Identity:
			recipient = identity.Recipient().String()
		case *age.HybridIdentity:
			recipient = identity.Recipient().String()
		default:
			return E.New("unknown identity: ", identity)
		}
		_, _ = os.Stdout.WriteString(recipient + "\n")
	}
	return nil
}

var commandAgeDecrypt = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt age",
	Args:  cobra.RangeArgs(1, 3),
	Run: func(cmd *cobra.Command, args []string) {
		key, reader, writer, err := parseAgeParameters(args)
		if err != nil {
			log.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		err = ageDecrypt(strings.NewReader(key), reader, writer)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func ageDecrypt(key, reader io.Reader, writer io.Writer) error {
	identities, err := age.ParseIdentities(key)
	if err != nil {
		return E.Cause(err, "parse age identities")
	}
	ageReader, err := age.Decrypt(armor.NewReader(reader), identities...)
	if err != nil {
		return E.Cause(err, "decrypt age")
	}
	_, err = bufio.Copy(writer, ageReader)
	if err != nil {
		return E.Cause(err, "copy age")
	}
	return nil
}

var commandAgeEncrypt = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt age",
	Args:  cobra.RangeArgs(1, 3),
	Run: func(cmd *cobra.Command, args []string) {
		key, reader, writer, err := parseAgeParameters(args)
		if err != nil {
			log.Fatal(err)
		}
		defer reader.Close()
		defer writer.Close()
		err = ageEncrypt(strings.NewReader(key), reader, writer)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func ageEncrypt(key, reader io.Reader, writer io.Writer) error {
	recipients, err := age.ParseRecipients(key)
	if err != nil {
		return E.Cause(err, "parse age recipients")
	}
	armorWriter := armor.NewWriter(writer)
	defer armorWriter.Close()
	ageWriter, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return E.Cause(err, "encrypt age")
	}
	defer ageWriter.Close()
	_, err = bufio.Copy(ageWriter, reader)
	if err != nil {
		return E.Cause(err, "copy age")
	}
	return nil
}

func parseAgeParameters(args []string) (key string, reader io.ReadCloser, writer io.WriteCloser, err error) {
	var inputName string
	if len(args) >= 2 {
		inputName = args[1]
	}
	reader, err = parseReader(inputName)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			_ = reader.Close()
		}
	}()
	var outputName string
	if len(args) >= 3 {
		outputName = args[2]
	}
	writer, err = parseWriter(outputName)
	if err != nil {
		return
	}
	key = args[0]
	return
}

func parseReader(name string) (io.ReadCloser, error) {
	switch name {
	case "", "-", "stdin":
		return io.NopCloser(os.Stdin), nil
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return file, nil
}

func parseWriter(name string) (io.WriteCloser, error) {
	switch name {
	case "", "-", "stdout":
		return nopWriteCloser{os.Stdout}, nil
	}
	file, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	return file, nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error {
	return nil
}
