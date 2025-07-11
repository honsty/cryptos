package cryptos

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
)

var (
	source = []string{
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w",
		"x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
		"K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"}
)

func Md5(s []byte) []byte {
	hash := md5.New()
	hash.Write(s)
	return hash.Sum(nil)
}

func Md5Str(s string) string {
	hash := md5.New()
	hash.Write([]byte(s))
	value := hash.Sum(nil)
	return hex.EncodeToString(value)
}

func Sha1(s []byte) []byte {
	hash := sha1.New()
	hash.Write(s)
	return hash.Sum(nil)
}

func Sha1Str(s string) string {
	hash := sha1.New()
	hash.Write([]byte(s))
	value := hash.Sum(nil)
	return hex.EncodeToString(value)
}

func Sha256(s []byte) []byte {
	hash := sha256.New()
	hash.Write(s)
	return hash.Sum(nil)
}

func Sha256Str(s []byte) string {
	return hex.EncodeToString(Sha256(s))
}

func Sha512(s []byte) []byte {
	hash := sha512.New()
	hash.Write(s)
	return hash.Sum(nil)
}

func Sha512Str(s []byte) string {
	return hex.EncodeToString(Sha512(s))
}

func Encrypt(s string) []byte {
	return Md5([]byte(s))
}

func Decrypt(b []byte) string {
	return hex.EncodeToString(b)
}

func ShortKey(key, str string) (url string, err error) {
	hash := []byte(hex.EncodeToString(Md5([]byte(key + str))))
	buffer := bytes.NewBufferString("")
	tempSubStrInt := binary.BigEndian.Uint32(hash[0:8])
	hexInt := tempSubStrInt & 0x3FFFFFFF
	for j := 0; j < 6; j++ {
		index := 0x0000003D & hexInt
		buffer.WriteString(source[index])
		hexInt = hexInt >> 5
	}
	url = buffer.String()
	return
}
