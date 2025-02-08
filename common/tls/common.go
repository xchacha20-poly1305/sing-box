package tls

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
)

const (
	VersionTLS10 = 0x0301
	VersionTLS11 = 0x0302
	VersionTLS12 = 0x0303
	VersionTLS13 = 0x0304

	// Deprecated: SSLv3 is cryptographically broken, and is no longer
	// supported by this package. See golang.org/issue/32716.
	VersionSSL30 = 0x0300
)

// CalculatePEMCertHash generates V2Ray style cert hash.
//
// https://github.com/v2fly/v2ray-core/blob/45e741bae00e2fda57dc8fb911c0ee16fe2e030b/transport/internet/tls/pin.go#L9-L36
func CalculatePEMCertHash(certContents []byte) []byte {
	var certChain [][]byte
	for {
		block, rest := pem.Decode(certContents)
		if block == nil {
			break
		}
		certChain = append(certChain, block.Bytes)
		certContents = rest
	}
	hash := CertChainHash(certChain)

	buffer := make([]byte, base64.StdEncoding.EncodedLen(len(hash)))
	base64.StdEncoding.Encode(buffer, hash)
	return buffer
}

func CertChainHash(rawCerts [][]byte) (hash []byte) {
	for _, cert := range rawCerts {
		sum := sha256.Sum256(cert)
		if hash == nil {
			hash = sum[:]
		} else {
			newSum := sha256.Sum256(append(hash, sum[:]...))
			hash = newSum[:]
		}
	}
	return
}
