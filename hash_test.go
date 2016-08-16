package cryptos

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestMd5(t *testing.T) {
	a := []byte{144, 1, 80, 152, 60, 210, 79, 176, 214, 150, 63, 125, 40, 225, 127, 114}
	b := Md5([]byte("abc"))
	if !bytes.Equal(a, b) {
		t.Fail()
	}
}

func TestEncrypt(t *testing.T) {
	a := "admin"
	b := Encrypt(a)
	if hex.EncodeToString(Md5([]byte(a))) != Decrypt(b) {
		t.Logf("a:%s b:%v", hex.EncodeToString(Md5([]byte(a))), Decrypt(b))
		t.Fail()
	}
}

func TestShortKey(t *testing.T) {
	key := "honsty.com"
	str := "http://www.baidu.com"
	short, err := ShortKey(key, str)
	t.Logf("%s %v", short, err)
}
