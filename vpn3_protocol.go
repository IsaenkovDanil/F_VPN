package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"crypto/aes"
	"crypto/cipher"
)

const (
	authTimeSkew = 90 * time.Second
)

type authMessage struct {
	Timestamp int64  `json:"ts"`
	Nonce     string `json:"nonce"`
	MAC       string `json:"mac"`
}

func buildAuthMessage(psk, wsPath string, ts int64, nonce []byte) (authMessage, error) {
	if len(nonce) == 0 {
		return authMessage{}, errors.New("nonce is empty")
	}
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(fmt.Sprintf("%d|", ts)))
	mac.Write(nonce)
	mac.Write([]byte("|"))
	mac.Write([]byte(wsPath))

	return authMessage{
		Timestamp: ts,
		Nonce:     base64.RawStdEncoding.EncodeToString(nonce),
		MAC:       base64.RawStdEncoding.EncodeToString(mac.Sum(nil)),
	}, nil
}

func verifyAuthMessage(psk, wsPath string, msg authMessage, now time.Time) ([]byte, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(msg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) < 8 {
		return nil, errors.New("nonce too short")
	}

	m, err := buildAuthMessage(psk, wsPath, msg.Timestamp, nonce)
	if err != nil {
		return nil, err
	}

	receivedMAC, err := base64.RawStdEncoding.DecodeString(msg.MAC)
	if err != nil {
		return nil, fmt.Errorf("decode mac: %w", err)
	}
	expectedMAC, err := base64.RawStdEncoding.DecodeString(m.MAC)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(receivedMAC, expectedMAC) {
		return nil, errors.New("invalid mac")
	}

	ts := time.Unix(msg.Timestamp, 0)
	if now.Sub(ts) > authTimeSkew || ts.Sub(now) > authTimeSkew {
		return nil, errors.New("timestamp skew too large")
	}

	return nonce, nil
}

func deriveSessionKey(psk string, nonce []byte, ts int64) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(nonce)
	mac.Write([]byte(fmt.Sprintf("|%d|vpn3-session", ts)))
	key := mac.Sum(nil)
	if len(key) < 32 {
		return nil, errors.New("derived key too short")
	}
	return key[:32], nil
}

func addPadding(payload []byte, maxPadding int) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, errors.New("payload too large")
	}
	if maxPadding < 0 {
		return nil, errors.New("maxPadding < 0")
	}

	paddingLen := 0
	if maxPadding > 0 {
		raw := make([]byte, 1)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		paddingLen = int(raw[0]) % (maxPadding + 1)
	}

	out := make([]byte, 2+len(payload)+paddingLen)
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	if paddingLen > 0 {
		if _, err := rand.Read(out[2+len(payload):]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func removePadding(frame []byte) ([]byte, error) {
	if len(frame) < 2 {
		return nil, errors.New("frame too short")
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[:2]))
	if payloadLen > len(frame)-2 {
		return nil, errors.New("invalid payload len")
	}
	return frame[2 : 2+payloadLen], nil
}

func encryptFrame(aeadKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	packet := append(nonce, sealed...)
	return packet, nil
}

func decryptFrame(aeadKey, packet []byte) ([]byte, error) {
	block, err := aes.NewCipher(aeadKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(packet) < 12 {
		return nil, errors.New("packet too short")
	}
	nonce := packet[:12]
	ciphertext := packet[12:]
	return aead.Open(nil, nonce, ciphertext, nil)
}
