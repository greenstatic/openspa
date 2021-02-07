package cryptography

import (
	"crypto/rsa"
	"github.com/greenstatic/openspalib/tools"
	"math/big"
	"testing"
)

// Testing key init copied from:
// https://golang.org/src/crypto/rsa/rsa_test.go
var test2048Key *rsa.PrivateKey

func init() {
	test2048Key = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: fromBase10("14314132931241006650998084889274020608918049032671858325988396851334124245188214251956198731333464217832226406088020736932173064754214329009979944037640912127943488972644697423190955557435910767690712778463524983667852819010259499695177313115447116110358524558307947613422897787329221478860907963827160223559690523660574329011927531289655711860504630573766609239332569210831325633840174683944553667352219670930408593321661375473885147973879086994006440025257225431977751512374815915392249179976902953721486040787792801849818254465486633791826766873076617116727073077821584676715609985777563958286637185868165868520557"),
			E: 3,
		},
		D: fromBase10("9542755287494004433998723259516013739278699355114572217325597900889416163458809501304132487555642811888150937392013824621448709836142886006653296025093941418628992648429798282127303704957273845127141852309016655778568546006839666463451542076964744073572349705538631742281931858219480985907271975884773482372966847639853897890615456605598071088189838676728836833012254065983259638538107719766738032720239892094196108713378822882383694456030043492571063441943847195939549773271694647657549658603365629458610273821292232646334717612674519997533901052790334279661754176490593041941863932308687197618671528035670452762731"),
		Primes: []*big.Int{
			fromBase10("130903255182996722426771613606077755295583329135067340152947172868415809027537376306193179624298874215608270802054347609836776473930072411958753044562214537013874103802006369634761074377213995983876788718033850153719421695468704276694983032644416930879093914927146648402139231293035971427838068945045019075433"),
			fromBase10("109348945610485453577574767652527472924289229538286649661240938988020367005475727988253438647560958573506159449538793540472829815903949343191091817779240101054552748665267574271163617694640513549693841337820602726596756351006149518830932261246698766355347898158548465400674856021497190430791824869615170301029"),
		},
	}
	test2048Key.Precompute()
}

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

// End test key init

// Tests the following functions:
// * RSA_SHA256_signature()
// * RSA_SHA256_signature_verify()
func TestRSA_SHA256_signature_and_verify(t *testing.T) {
	tests := []struct {
		inputData   []byte
		expectedErr bool
		onErrorStr  string
	}{
		{
			[]byte{0x74, 0x65, 0x73, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x20, 0x70, 0x61,
				0x69, 0x6E},
			false,
			"failed to sign/verify data with completely valid function calls",
		},
		{
			[]byte{0x74},
			false,
			"failed to sign/verify data with completely valid function calls",
		},
		{
			[]byte{},
			true,
			"failed to return error on empty signature data slice function call",
		},
	}

	for i, test := range tests {
		signature, err := RSA_SHA256_signature(test.inputData, test2048Key)

		if err != nil != test.expectedErr {
			t.Errorf("Unexpected error for test case: %d, err: %s, reason: %s", i, err, test.onErrorStr)
			continue
		}

		if test.expectedErr {
			continue
		}

		valid := RSA_SHA256_signature_verify(test.inputData, &test2048Key.PublicKey, signature)

		if !valid {
			t.Errorf("Failed to verify signature for test case: %d, reason: %s", i, test.onErrorStr)
		}

	}
}

// Tests the following functions:
// * RSA_encrypt()
// * RSA_decrypt()
func TestRSA_encrypt_and_decrypt(t *testing.T) {
	tests := []struct {
		inputData   []byte
		expectedErr bool
		onErrorStr  string
	}{
		{
			[]byte{0x74, 0x65, 0x73, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x61, 0x20, 0x70, 0x61,
				0x69, 0x6E},
			false,
			"failed to encrypt/decrypt data with completely valid function calls",
		},
		{
			[]byte{0x74},
			false,
			"failed to encrypt/decrypt data with completely valid function calls",
		},
		{
			[]byte{},
			true,
			"failed to return error when input data slice is empty",
		},
	}

	for i, test := range tests {
		ciphertext, err := RSA_encrypt(test.inputData, &test2048Key.PublicKey)

		if err != nil != test.expectedErr {
			t.Errorf("Unexpected error while encrypting for test case: %d, err: %s, reason: %s",
				i, err, test.onErrorStr)
			continue
		}

		if test.expectedErr {
			continue
		}

		plaintext, err := RSA_decrypt(ciphertext, test2048Key)

		if err != nil != test.expectedErr {
			t.Errorf("Unexpected error while decrypting for test case: %d, err: %s, reason %s",
				i, err, test.onErrorStr)
		}

		if !tools.CompareTwoByteSlices(plaintext, test.inputData) {
			t.Errorf("Decrypted content after encryption is not the same as the initial encrypted content for test case: %d, reason: %s",
				i, test.onErrorStr)
		}

	}
}
