package cryptos

import (
	"bytes"
	"encoding/hex"
	"testing"
	"crypto/sha256"
	"crypto/sha1"
	"crypto/sha512"
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

func TestSha1(t *testing.T) {
	hash:=sha1.New()
	hash.Write([]byte("admin"))
	md:=hash.Sum(nil)
	t.Log(hex.EncodeToString(md))
}

func TestSha256(t *testing.T){
	hash:=sha256.New()
	hash.Write([]byte("admin"))
	md:=hash.Sum(nil)
	t.Log(hex.EncodeToString(md))
}


func TestSha512(t *testing.T){
	hash:=sha512.New()
	hash.Write([]byte("admin"))
	md:=hash.Sum(nil)
	t.Log(hex.EncodeToString(md))
}

/*
go test -test.run TestSha1
go test -test.run TestSha256
*/