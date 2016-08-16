package des

import (
	"common/crypto/padding"
	icipher "crypto/cipher"
	ides "crypto/des"
	"errors"
)

var (
	ErrDesBlockSize = errors.New("plaintext is not a multiple of the block size")
	ErrDesSrcSize   = errors.New("ciphertext too short")
	ErrDesIVSize    = errors.New("iv size is not a block size")
)

// CBCEncrypt aes ecb encrypt.
func CBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if p == nil {
		if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
			return nil, ErrDesSrcSize
		}
	} else {
		src = p.Padding(src, ides.BlockSize)
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func CBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(src) < ides.BlockSize || len(src)%ides.BlockSize != 0 {
		return nil, ErrDesSrcSize
	}
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, ides.BlockSize)
	}
}

// CBCEncrypt aes ecb encrypt.
func TripleCBCEncrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	if p == nil {
		if len(src) < ides.BlockSize*3 || len(src)%ides.BlockSize != 0 {
			return nil, ErrDesSrcSize
		}
	} else {
		src = p.Padding(src, ides.BlockSize)
	}
	mode := icipher.NewCBCEncrypter(block, iv)
	encryptText := make([]byte, len(src))
	mode.CryptBlocks(encryptText, src)
	return encryptText, nil
}

// CBCDecrypt aes cbc decrypt.
func TripleCBCDecrypt(src, key, iv []byte, p padding.Padding) ([]byte, error) {
	if len(key) < ides.BlockSize*3 || len(key)%ides.BlockSize != 0 {
		return nil, ErrDesSrcSize
	}
	if len(iv) != ides.BlockSize {
		return nil, ErrDesIVSize
	}
	block, err := ides.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	mode := icipher.NewCBCDecrypter(block, iv)
	decryptText := make([]byte, len(src))
	mode.CryptBlocks(decryptText, src)
	if p == nil {
		return decryptText, nil
	} else {
		return p.Unpadding(decryptText, ides.BlockSize*3)
	}
}
