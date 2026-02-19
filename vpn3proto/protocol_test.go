package vpn3proto

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthOK(t *testing.T) {
	nonce := []byte("12345678abcdefgh")
	ts := time.Now().Unix()
	msg, err := BuildAuthMessage("psk", "/x", ts, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAuthMessage("psk", "/x", msg, time.Unix(ts, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, nonce) {
		t.Fatal("nonce mismatch")
	}
}

func TestCryptoPaddingAndFrame(t *testing.T) {
	base := DeriveBaseKey("psk", []byte("12345678abcdefgh"), 11)
	key := DeriveTrafficKey(base, 3, "c2s")
	plain := MakeDataFrame([]byte{1, 2, 3, 4})
	pad, err := AddPadding(plain, 32)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := EncryptFrame(key, pad)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptFrame(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	unpad, err := RemovePadding(dec)
	if err != nil {
		t.Fatal(err)
	}
	k, body, err := ParseFrame(unpad)
	if err != nil {
		t.Fatal(err)
	}
	if k != FrameData || !bytes.Equal(body, []byte{1, 2, 3, 4}) {
		t.Fatal("bad frame parse")
	}
}
