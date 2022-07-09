package openspalib_old

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
)

// Using a RSA public key we encrypt a slice of byte data.
func rsaEncrypt(data []byte, pubKey *rsa.PublicKey) (ciphertext []byte, err error) {
	if len(data) == 0 {
		return nil, errors.New("cannot encrypt empty data slice")
	}

	ciphertext, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)

	if err != nil {
		// failed to encrypt the plaintext using the public RSA key
		return nil, err
	}

	return
}

// Using the RSA private key we decrypt a slice of byte data that was encrypted using the corresponding RSA public key.
func rsaDecrypt(data []byte, privKey *rsa.PrivateKey) (plaintext []byte, err error) {
	if len(data) == 0 {
		return nil, errors.New("cannot decrypt empty data slice")
	}

	plaintext, err = rsa.DecryptPKCS1v15(rand.Reader, privKey, data)

	if err != nil {
		// failed to decrypt the ciphertext using the private RSA key
		return nil, err
	}

	return
}

// parsePkcs8 parses the contents of a PEM file into a private and public key. Currently we support only RSA.
func parsePkcs8(pkcs8Pem []byte) (crypto.PrivateKey, crypto.PublicKey, error) {
	privBlock, _ := pem.Decode(pkcs8Pem)
	if privBlock == nil {
		return nil, nil, errors.New("pem decode is nil")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		panic(err)
	}

	privateKey := privKey.(*rsa.PrivateKey) // TODO - make this generic
	publicKey := privateKey.Public()

	return privateKey, publicKey, nil
}

// TestingRsaKeyPair1 should NOT BE USED IN PRODUCTION. This is should be only used for testing purposes. You should
// generate your own private key using OpenSSL or similar RSA implementation.
func TestingRsaKeyPair1() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Generated by running:
	// `openssl genpkey -out example.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
	// This is a PKCS#8 private key file
	privateKeyPem := `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCsB1c7eKuYHyRB
AR3yhEM+K31+2Q15izQHuV4NfT615hpQOii3C3cBULpJuoJFkR+F/QPRIh7sDdYW
5Anm31rH1kDaIuAIP3Z2xZ4+5dGR0Y84VlKFC31Ud5vAyj0Mvyn+pjpUB5KcSlc+
comnzFfJ54nS+gIz0dhppGb8uB47Y/W63ZoSzI++HZeiUXByn+dFD1MgXlSgNZ38
PdAAbLlbEUf/HCUSxRwAaHCZwn0l+uURYjywoya61UQeYl7Zp8pmONyXLpq1D4a3
MAW1hbAnqCbSWLx5lF9u17cRFLGg9cJYDR6PaX7ZvN/NMSgsqIQvCb6VBTFO4b3P
MnLZ1SMRAgMBAAECggEAcyhK1c3WmHOoUjeMM48kcFauoJ5t7cIop08ITeFcfGm3
jaMRJE9xb5j5y2cl06ntP0V7K6E6r+wnN5WZp0o3O/UJ3rxf2kWZaLKrVxGDM6jj
xePLQ7LISCX1Rp5bNdA2LXhbLWsQUr1VH8GOspwQ3GC5m1iu5r9/rmBWbLBX1Irh
CHFlVclSiYvG6FcxeiVy4PKF+WLSQsa9jDiwKrShYjGSghCGPwg/yC2mZl2yHMtm
OrvxjIex1XRTdkmkYH7v6JzrYVMO0XTqKG2lZLMHlGPUVUNHixMRYGbFqVTVrXOK
zF47IOliacf73Ha8q6sWj2d8ojb9fsYY4glcJGu+AQKBgQDhKc1DneKPL+/9/d4X
H0swomXMwmlwIYhX4YOhLJiPIF+3ERADEcHAotxlmyhJMSizzL/BISfzK0zildVD
tT8Z0fW3wEOynmGgNudyOKfaCJ2sG8IfvxsjYjOPWmQhnJJFlE0GHw775HmZT6d0
WmuJ55R0Vb+vPqdoQlsI7aL0sQKBgQDDlqVL5M1KaFccGe0RfDsbp1P93NQkIYov
Mf2/WoakgkCFU1qKMJdXRzl7XVfzve/q0t5uykO5Iqsr5c3qKnPVMr5xkPqmPXxL
/geAg+VGV9VbQq8plB1Zdlu6Jk3hxhKA9fOB3rybUcXt+OX1I5zbIKK9qkOFGV/H
/zYzf4gsYQKBgQDKRl5TXzQYBC2qVHU++mr2zv16/C/yfv1YTYyNr12CPsgd0qM6
zqnrn6M1WDTRw+rX05l0K5ATIRQZ/havk9STIo6Gu59ViHkVkB1N/F22PsU+x1UW
Zf1ARUkigEax91FkVnz3gdFZMwCWXPuHSG+RXMx90ka4bSXBQNM9axZYkQKBgQC3
EmfQHO6nCfkXXZEP/8dXwAyXHz8WPqqYOGO526MRkrWP1hB2LrtJv2ondZygkhVi
KFR5QSuYu8GaijRuTaQ0V5X4uOpT9lNE0hb1jP9rE0WqcUWBVpkOJwH+wGG/xWWG
fjCaTAEgJK9uar3b8aSdWvPZMeiXScPkcJasJ2AvoQKBgQCl5l7hrWSDrsCpNtJO
g5Ajso80usVvseocVPBiAC8MuIsZg9rooxYGo16OFCXjs7IhRVPtzMrhMjFIK5Qt
EOsk9NgbHN27rL05a9iIxxbgA8yypulimBqqfM584UkgUq8E6zF/qWWyUEDTsVkD
z9xMdUkomGPlRmAOjd399ddJCA==
-----END PRIVATE KEY-----`

	priv, pub, err := parsePkcs8([]byte(privateKeyPem))
	if err != nil {
		panic(err)
	}

	return priv.(*rsa.PrivateKey), pub.(*rsa.PublicKey)
}

// TestingRsaKeyPair2 should NOT BE USED IN PRODUCTION. This is should be only used for testing purposes. You should
// generate your own private key using OpenSSL or similar RSA implementation.
func TestingRsaKeyPair2() (*rsa.PrivateKey, *rsa.PublicKey) {
	// Generated by running:
	// `openssl genpkey -out example.key -algorithm RSA -pkeyopt rsa_keygen_bits:2048`
	// This is a PKCS#8 private key file
	privateKeyPem := `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC0JlVJOSFxVkVT
tm0iQb8CuSbBFxRx4OcjcUp/9Y5n7JgFsh8KMxcWxLwLyurmd5Q08ItqIsOhPdhE
L6fMxKd62ld6cZzk8lB2/hzcDUDwyr4BLvouwfzE+5ibWi+cDrF5Y+iz11jkEdR8
lxIi2mDbZexO5aVLliRguKEMZWg4PYIWA/fIw84xP32zQteayFszFK3gJ2dPjF+I
2vfhHPaUjX/q+7ZRdzVmMF8EhKbFcg6IPtIiQaCJVNN6CZovWWN5CYOCzBupMcun
j+XxKbJO+EMC9tN6rYvJuDZociXAiLxQ1TNeRSv++CtAKPVsYhJs/Br/sbmwjMki
wExCha8nAgMBAAECggEAQu5fD3Zva2lvFnwXrfuZWQyrTmAh03GIzs0/razw/MGV
dcBI8gQrVuU/LG52uavB361jTsqdvmF44VSHVnfV9bn7eF2PuiwhIySkWkl+UDgz
QcNPZmHiZNlJSKbIO4XmAEDTa0XeG9ZYCPYj4dka1UjX9DQ0JpIg7+KIy0892m64
GOc/2Kou9JcwdkunSXBJ+o1dLn8gZ2Ithe8136UzsEm5B6XpNFDYozaDoTleHchn
R7qfgnN4MdIxXNRQDeM4fi5zPDgWQj0v7Od+rWAq+jDzHK8igXGV5iQQQaw5b5Jd
/uP55AwvI2oeAUYQgzjc2Cv0thOrA5r9IpUgP+s1uQKBgQDfzJfs90tMFQGw2s3s
ZFE1TDMAW89dqEbEUuW7rmBL2g1KADU2YCWA2OsERx/WBpPpFZsSIJgZlcdU+Dg2
hns+WZ7qygkQyn5hG4kfGDGKBAf0JqtF18nZvuDpREv6+P4L+7nxvj8M5HN0naiH
WXibTMvBNsYyyytcyKTa05wCjQKBgQDOEfVNYcLzJXXhT44619iLFpGGB1ejpLNO
28i4ybl8/QnHsn7putt1EatZq4/97qW9O90nGpSA2a9LRfIDyEphX3o55sRMkS2V
pwre+l+Og7Fej7svw2BFByFLCo2x9Q7XTeei0HBnQNwGo/kOiuw9goa+YV2nLlM7
fQqvlxolgwKBgHDz/PXftkQ3Efxl4qrd0tLYm6EhtV5q0RTDVinMj9OYwT5JLpI8
IpGOacdl8l5+QWbRvct/YeT/4HQ1N4HljAxjBT8xKzQrT2/JiwKDnnUvJaiHX8hH
ahwZJ8Dz9Hk99FKuASJOx9nE77S64dU2RhXzw57H+26ldkRFDFdZmBL9AoGBAIkF
Rd+7Rn6YhQZY+NDFnxX03rSJA0wrgpLH73J3p5+lPTCMznipp6zzH8WTHz6QxaHL
QWTz9pSqqjVZ/+9l6ZdPfh0sBZCH5BCjLsZPIuTHSlP/LE85ETU05X1ZOhh/QuwE
wCXxhRwS83py43M5CpZnySKj6Tr1waBHp6hTx63zAoGBAIhvze4AmXLkBd+vHAdj
MJ0NPCVa7jee57qcKrDHUDCoq9an0z41YS5Wc/feBVDsf/c+JcSl4MsZNfeBn2g5
8JlclAeEO3jbblcuUJO19SZlsNBaTmHSCYgGMSVg3nuIBLORGd5tQEwi3Qsd+6fH
luhg1Ra2sRiEVNilg1/VjGF/
-----END PRIVATE KEY-----`

	priv, pub, err := parsePkcs8([]byte(privateKeyPem))
	if err != nil {
		panic(err)
	}

	return priv.(*rsa.PrivateKey), pub.(*rsa.PublicKey)
}