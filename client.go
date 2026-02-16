package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// 1. ПУБЛИЧНЫЙ КЛЮЧ СЕРВЕРА (ПАСПОРТ)
// !!! ЗАПУСТИ SERVER.GO, СКОПИРУЙ КЛЮЧ И ВСТАВЬ СЮДА !!!
const serverEdPublicKeyHex = "144306fd37ae5cafffc967f1fb2d33867ca5e2a8fad2544605cbe64a72511540"

const psk = "MySecretPassword"

func main() {
	// --- ПОДГОТОВКА ---
	serverEdPubBytes, _ := hex.DecodeString(serverEdPublicKeyHex)
	serverEdPubKey := ed25519.PublicKey(serverEdPubBytes)
	fmt.Println("Server Identity Loaded (Passport).")

	// --- 1. ГЕНЕРАЦИЯ КЛЮЧЕЙ (X25519) ---
	clientPub, clientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	// --- 2. ПОДКЛЮЧЕНИЕ ---
	conn, err := net.Dial("tcp", "127.0.0.1:9000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("Connected to server...")

	// --- 3. ОТПРАВКА CLIENT HELLO (72 байта) ---
	timestamp := time.Now().Unix()
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(timestamp))

	payload := append(timeBuf, clientPub[:]...)

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(payload)
	signature := mac.Sum(nil)

	packet := append(payload, signature...)
	conn.Write(packet)
	fmt.Println("Client Hello SENT. Waiting for response...")

	// --- 4. ЧТЕНИЕ SERVER HELLO (136 байт) ---
	// [ Time (8) ] + [ ServerPub (32) ] + [ Signature (64) ] + [ HMAC (32) ]
	response := make([]byte, 136)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		panic(err)
	}
	fmt.Println("Received 136 bytes from Server.")

	// --- 5. ПРОВЕРКА HMAC ---
	serverPayload := response[:104]
	serverHMAC := response[104:]

	mac2 := hmac.New(sha256.New, []byte(psk))
	mac2.Write(serverPayload)
	expectedHMAC := mac2.Sum(nil)

	if !hmac.Equal(serverHMAC, expectedHMAC) {
		panic("❌ SERVER HMAC INVALID! (Wrong password?)")
	}
	fmt.Println("✅ Server HMAC Valid.")

	// --- 6. РАЗБОР ДАННЫХ ---
	serverTime := binary.BigEndian.Uint64(serverPayload[:8])
	serverPub := serverPayload[8:40]   // Временный ключ сервера (для шифрования)
	serverSig := serverPayload[40:104] // Подпись (для проверки личности)

	fmt.Printf("Server Time: %d\n", serverTime)

	// --- 7. ПРОВЕРКА ПОДПИСИ (САМОЕ ВАЖНОЕ!) ---
	// Сервер подписывал: [ ClientPub ] + [ ServerPub ]
	// Мы должны собрать те же данные и проверить подпись "Паспортом"
	verifyMsg := append(clientPub[:], serverPub...)

	isValid := ed25519.Verify(serverEdPubKey, verifyMsg, serverSig)

	if !isValid {
		panic("❌ FAKE SERVER! Signature verification failed.")
	}

	fmt.Println("✅ SERVER IDENTITY VERIFIED! This is the real server.")
	fmt.Println("Step 9 Complete: Handshake Validated.")

	// Чтобы компилятор не ругался
	_ = clientPriv
}
