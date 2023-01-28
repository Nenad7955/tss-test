package binance_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	ecdsa_scheme "github.ibm.com/fabric-security-research/tss/mpc/binance/ecdsa"
	. "github.ibm.com/fabric-security-research/tss/types"
	"testing"
)

func TestThresholdBinanceECDSA(t *testing.T) {
	n := 4

	var verifySig signatureVerifyFunc

	var signatureAlgorithms func([]*commLogger) (func(uint16) KeyGenerator, func(uint16) Signer)

	verifySig = verifySignatureECDSA
	signatureAlgorithms = ecdsaKeygenAndSign

	testScheme(t, n, signatureAlgorithms, verifySig)
}

func ecdsaKeygenAndSign(loggers []*commLogger) (func(id uint16) KeyGenerator, func(id uint16) Signer) {
	kgf := func(id uint16) KeyGenerator {
		return ecdsa_scheme.NewParty(id, loggers[id-1])
	}

	sf := func(id uint16) Signer {
		return ecdsa_scheme.NewParty(id, loggers[id-1])
	}
	return kgf, sf
}

func verifySignatureECDSA(pkBytes []byte, t *testing.T, msg string, signature []byte) {
	pk, err := x509.ParsePKIXPublicKey(pkBytes)
	assert.NoError(t, err)

	assert.True(t, ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), sha256Digest([]byte(msg)), signature))
}
