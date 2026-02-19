package main

import (
	"bytes"
	"testing"
	"time"
)

func TestAuthRoundTrip(t *testing.T) {
	psk := "test-psk"
	path := "/vpn"
	nonce := []byte("12345678abcdefgh")
	ts := time.Now().Unix()

	msg, err := buildAuthMessage(psk, path, ts, nonce)
	if err != nil {
		t.Fatal(err)
	}
	gotNonce, err := verifyAuthMessage(psk, path, msg, time.Unix(ts, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotNonce, nonce) {
		t.Fatalf("nonce mismatch")
	}
}

func TestPaddingAndCryptoRoundTrip(t *testing.T) {
	msg := []byte("hello")
	padded, err := addPadding(msg, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) < len(msg)+2 {
		t.Fatalf("padding too short")
	}
	key, err := deriveSessionKey("psk", []byte("12345678abcdefgh"), 1)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encryptFrame(key, padded)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := decryptFrame(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := removePadding(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "hello" {
		t.Fatalf("unexpected payload: %q", string(plain))
	}
}
