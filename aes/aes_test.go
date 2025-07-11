package aes

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
)

func TestGcmAes(t *testing.T) {
	key := make([]byte, 32) // AES-256 密钥长度为 32 字节
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	plaintext := []byte("机密数据")
	t.Log(string(plaintext))
	ciphertext, err := GCMEncrypt(plaintext, key)
	if err != nil {
		t.Fatalf("err=%v\n", err)
	}
	t.Logf("加密后：%s\n", hex.EncodeToString(ciphertext))

	plaintext, err = GCMDecrypt(ciphertext, key)
	if err != nil {
		t.Fatalf("err=%#v\n", err)
	}
	t.Logf("解密后:%s\n", string(plaintext))
}
