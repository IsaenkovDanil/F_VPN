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

const psk = "MySecretPassword"

func main() {
	// 1. Генерируем "Паспорт" сервера (Ed25519)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Println("=== SERVER STARTED ===")
	fmt.Println("Server Identity (Ed25519 Public Key):")
	fmt.Println(hex.EncodeToString(pub))
	fmt.Println("!!! COPY THIS KEY TO CLIENT NOW !!!")
	fmt.Println()

	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Waiting for client on port 9000...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}

		// Запускаем обработку клиента в отдельной горутине, чтобы не блокировать остальных
		go handleConnection(conn, priv)
	}
}

func handleConnection(conn net.Conn, serverEdPriv ed25519.PrivateKey) {
	defer conn.Close()
	fmt.Println("\nClient connected:", conn.RemoteAddr())

	// --- 1. ЧТЕНИЕ (Client Hello) ---
	buffer := make([]byte, 72)
	if _, err := io.ReadFull(conn, buffer); err != nil {
		fmt.Println("Error reading packet:", err)
		return
	}

	// --- 2. ПРОВЕРКА (HMAC) ---
	payload := buffer[:40]
	receivedSignature := buffer[40:]

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(payload)
	expectedSignature := mac.Sum(nil)

	if !hmac.Equal(receivedSignature, expectedSignature) {
		fmt.Println("❌ HMAC VERIFICATION FAILED!")
		return
	}
	fmt.Println("✅ Client HMAC Valid.")

	// --- 3. ИЗВЛЕЧЕНИЕ ДАННЫХ ---
	clientTimestamp := binary.BigEndian.Uint64(payload[:8])
	clientPub := payload[8:40] // [32]byte

	// Превращаем срез в массив [32]byte для X25519
	var clientPubArr [32]byte
	copy(clientPubArr[:], clientPub)

	fmt.Printf("Client Timestamp: %d\n", clientTimestamp)
	fmt.Printf("Client Ephemeral Key: %x...\n", clientPubArr[:5])

	// --- ШАГ 8: ФОРМИРОВАНИЕ ОТВЕТА (Server Hello) ---

	// А. Генерируем ВРЕМЕННЫЙ ключ сервера (X25519)
	serverPub, serverPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Key generation error:", err)
		return
	}

	// Б. ВРЕМЯ (8 байт)
	serverTime := time.Now().Unix()
	serverTimeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(serverTimeBuf, uint64(serverTime))

	// В. ПОДПИСЬ (Ed25519) - Доказываем, что мы настоящий сервер
	// Подписываем: [ ClientPub (32) ] + [ ServerPub (32) ]
	// Это связывает ответ сервера с конкретным запросом клиента
	signatureMessage := append(clientPubArr[:], serverPub[:]...)
	signature := ed25519.Sign(serverEdPriv, signatureMessage) // 64 байта

	// Г. СБОРКА PAYLOAD (104 байта)
	// [ Time (8) ] + [ ServerPub (32) ] + [ Signature (64) ]
	serverPayload := append(serverTimeBuf, serverPub[:]...)
	serverPayload = append(serverPayload, signature...)

	// Д. HMAC (Печать PSK) - Скрываем ответ
	mac2 := hmac.New(sha256.New, []byte(psk))
	mac2.Write(serverPayload)
	serverHMAC := mac2.Sum(nil) // 32 байта

	// Е. ИТОГОВЫЙ ПАКЕТ (136 байт)
	serverPacket := append(serverPayload, serverHMAC...)

	fmt.Printf("Sending Server Hello (%d bytes)...\n", len(serverPacket))

	// Ж. ОТПРАВКА
	if _, err := conn.Write(serverPacket); err != nil {
		fmt.Println("Error sending packet:", err)
		return
	}

	fmt.Println("Server Hello SENT! Handshake almost complete on server side.")

	// Чтобы компилятор не ругался
	_ = serverPriv
}
