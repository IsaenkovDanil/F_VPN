package vpn3proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	AuthTimeSkew = 90 * time.Second

	FrameData     byte = 1
	FrameRekey    byte = 2
	FrameRekeyAck byte = 3
)

type AuthMessage struct {
	Timestamp int64  `json:"ts"`
	Nonce     string `json:"nonce"`
	MAC       string `json:"mac"`
}

func BuildAuthMessage(psk, wsPath string, ts int64, nonce []byte) (AuthMessage, error) {
	if len(nonce) < 8 {
		return AuthMessage{}, errors.New("nonce must be >= 8 bytes")
	}
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(fmt.Sprintf("%d|", ts)))
	mac.Write(nonce)
	mac.Write([]byte("|" + wsPath))
	return AuthMessage{Timestamp: ts, Nonce: base64.RawStdEncoding.EncodeToString(nonce), MAC: base64.RawStdEncoding.EncodeToString(mac.Sum(nil))}, nil
}

func VerifyAuthMessage(psk, wsPath string, msg AuthMessage, now time.Time) ([]byte, error) {
	nonce, err := base64.RawStdEncoding.DecodeString(msg.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	expected, err := BuildAuthMessage(psk, wsPath, msg.Timestamp, nonce)
	if err != nil {
		return nil, err
	}
	gotMAC, err := base64.RawStdEncoding.DecodeString(msg.MAC)
	if err != nil {
		return nil, err
	}
	expMAC, _ := base64.RawStdEncoding.DecodeString(expected.MAC)
	if !hmac.Equal(gotMAC, expMAC) {
		return nil, errors.New("bad mac")
	}
	ts := time.Unix(msg.Timestamp, 0)
	if now.Sub(ts) > AuthTimeSkew || ts.Sub(now) > AuthTimeSkew {
		return nil, errors.New("auth timestamp skew too large")
	}
	return nonce, nil
}

func DeriveBaseKey(psk string, nonce []byte, ts int64) []byte {
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(nonce)
	mac.Write([]byte(fmt.Sprintf("|%d|vpn3-base", ts)))
	return mac.Sum(nil)[:32]
}

func DeriveTrafficKey(base []byte, generation uint32, direction string) []byte {
	mac := hmac.New(sha256.New, base)
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, generation)
	mac.Write(buf)
	mac.Write([]byte("|" + direction))
	return mac.Sum(nil)[:32]
}

func AddPadding(payload []byte, maxPadding int) ([]byte, error) {
	if len(payload) > 65535 {
		return nil, errors.New("payload too large")
	}
	if maxPadding < 0 {
		return nil, errors.New("maxPadding < 0")
	}
	pad := 0
	if maxPadding > 0 {
		r := []byte{0}
		if _, err := rand.Read(r); err != nil {
			return nil, err
		}
		pad = int(r[0]) % (maxPadding + 1)
	}
	out := make([]byte, 2+len(payload)+pad)
	binary.BigEndian.PutUint16(out[:2], uint16(len(payload)))
	copy(out[2:], payload)
	if pad > 0 {
		_, _ = rand.Read(out[2+len(payload):])
	}
	return out, nil
}

func RemovePadding(frame []byte) ([]byte, error) {
	if len(frame) < 2 {
		return nil, errors.New("frame too short")
	}
	l := int(binary.BigEndian.Uint16(frame[:2]))
	if l > len(frame)-2 {
		return nil, errors.New("invalid payload len")
	}
	return frame[2 : 2+l], nil
}

func EncryptFrame(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, nonce, plaintext, nil)...), nil
}

func DecryptFrame(key, packet []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(packet) < ns {
		return nil, errors.New("packet too short")
	}
	return aead.Open(nil, packet[:ns], packet[ns:], nil)
}

func MakeDataFrame(ipPacket []byte) []byte {
	out := make([]byte, 1+len(ipPacket))
	out[0] = FrameData
	copy(out[1:], ipPacket)
	return out
}

func MakeRekeyFrame(nextGen uint32, ack bool) []byte {
	kind := FrameRekey
	if ack {
		kind = FrameRekeyAck
	}
	out := make([]byte, 5)
	out[0] = kind
	binary.BigEndian.PutUint32(out[1:], nextGen)
	return out
}

func ParseFrame(frame []byte) (kind byte, body []byte, err error) {
	if len(frame) < 1 {
		return 0, nil, errors.New("empty frame")
	}
	return frame[0], frame[1:], nil
}
