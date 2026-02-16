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

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
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
	serverPubSlice := serverPayload[8:40] // Временный ключ сервера (для шифрования)
	serverSig := serverPayload[40:104]    // Подпись (для проверки личности)

	fmt.Printf("Server Time: %d\n", serverTime)

	// Превращаем slice в массив [32]byte (нужно для математики)
	var serverPubArr [32]byte
	copy(serverPubArr[:], serverPubSlice)
	// --- 7. ПРОВЕРКА ПОДПИСИ (САМОЕ ВАЖНОЕ!) ---
	// Сервер подписывал: [ ClientPub ] + [ ServerPub ]
	// Мы должны собрать те же данные и проверить подпись "Паспортом"
	verifyMsg := append(clientPub[:], serverPubSlice...)

	isValid := ed25519.Verify(serverEdPubKey, verifyMsg, serverSig)

	if !isValid {
		panic("❌ FAKE SERVER! Signature verification failed.")
	}

	fmt.Println("✅ SERVER IDENTITY VERIFIED! This is the real server.")

	// --- 8. МАГИЯ: ВЫЧИСЛЕНИЕ ОБЩЕГО СЕКРЕТА (ECDH) ---
	// Мы берем: НАШ Приватный ключ + ЕГО Публичный ключ
	// Результат: Shared Secret (32 байта)
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, clientPriv, &serverPubArr)

	fmt.Printf("🔹 SHARED SECRET (Internal): %x...\n", sharedSecret[:5])

	// --- 9. HKDF: СОЗДАНИЕ КЛЮЧЕЙ ШИФРОВАНИЯ ---
	// Превращаем "сырой" секрет в два красивых ключа
	hash := sha256.New
	kdf := hkdf.New(hash, sharedSecret[:], nil, nil)

	// Нам нужно 2 ключа по 32 байта (AES-256)
	// 1. Ключ для отправки (Client -> Server)
	// 2. Ключ для приема (Server -> Client)
	keyWriter := make([]byte, 32)
	keyReader := make([]byte, 32)

	io.ReadFull(kdf, keyWriter)
	io.ReadFull(kdf, keyReader)

	fmt.Println("\n🎉 HANDSHAKE COMPLETE! KEYS GENERATED:")
	fmt.Printf("🔑 Key Client->Server: %x\n", keyWriter)
	fmt.Printf("🔑 Key Server->Client: %x\n", keyReader)

	// Теперь мы можем использовать эти ключи для шифрования реальных данных!

	// Чтобы компилятор не ругался
	_ = clientPriv
}
