package cryptos

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

var (
	errNotAnRsaPublicKey  = errors.New("Value returned from ParsePKIXPublicKey was not an RSA public key")
	errNotAnRsaPrivateKey = errors.New("Value returned from ParsePKCS8PrivateKey was not an RSA private key")
)

func GetPublicKey(public string) (publicKey *rsa.PublicKey, err error) {
	publicKeyByte, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		return
	}
	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyByte)
	if err != nil {
		return
	}
	var ok bool
	publicKey, ok = publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		err = errNotAnRsaPublicKey
		return
	}
	return
}

func GetPrivateKey(private string) (privateKey *rsa.PrivateKey, err error) {
	privateKeyByte, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return
	}
	privateInterface, err := x509.ParsePKCS8PrivateKey(privateKeyByte)
	if err != nil {
		return
	}
	var ok bool
	privateKey, ok = privateInterface.(*rsa.PrivateKey)
	if !ok {
		err = errNotAnRsaPrivateKey
		return
	}
	return
}
