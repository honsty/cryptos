package aes

import (
	iaes "crypto/aes"
	icipher "crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/honsty/cryptos/cipher"
	"github.com/honsty/cryptos/padding"
)

var (
	ErrAesBlockSize = errors.New("plaintext is not a multiple of the block size")
	ErrAesSrcSize   = errors.New("ciphertext too short")
	ErrAesIVSize    = errors.New("iv size is not a block size")
)

// ECBEncrypt aes ecb encrypt.
func ECBEncrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	if p == nil {
		if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
			return nil, ErrAesBlockSize
		}
	} else {
		src = p.Padding(src, iaes.BlockSize)
	}
	b, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBEncrypter(b)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// ECBDecrypt aes ecb decrypt.
func ECBDecrypt(src, key []byte, p padding.Padding) ([]byte, error) {
	if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
		return nil, ErrAesSrcSize
	}
	b, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewECBDecrypter(b)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, iaes.BlockSize)
	}
}

// CBCEncrypt aes cbc encrypt.
func CBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	if p == nil {
		// if no padding check src
		if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
			return nil, ErrAesSrcSize
		}
	} else {
		// padding
		src = p.Padding(src, iaes.BlockSize)
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func CBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	// check src
	if len(src) < iaes.BlockSize || len(src)%iaes.BlockSize != 0 {
		return nil, ErrAesSrcSize
	}
	// check iv
	if len(iv) != iaes.BlockSize {
		return nil, ErrAesIVSize
	}
	block, err := iaes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, iaes.BlockSize)
	}
}

// GCMEncrypt aes gcm encrypt. AES-256 密钥长度为 32 字节
func GCMEncrypt(src, key []byte) ([]byte, error) {
	block, err := iaes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesGcm, err := icipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce := make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	ciphertext := aesGcm.Seal(nonce, nonce, src, nil)
	return ciphertext, nil
}

// GCMDecrypt aes gcm decrypt
func GCMDecrypt(src, key []byte) ([]byte, error) {
	block, err := iaes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesGcm, err := icipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonceSize := aesGcm.NonceSize()
	if len(src) < nonceSize {
		panic("ciphertext too shart")
	}
	receivedNonce := src[:nonceSize]
	receivedCiphertext := src[nonceSize:]
	plaintext, err := aesGcm.Open(nil, receivedNonce, receivedCiphertext, nil)
	return plaintext, err
}
