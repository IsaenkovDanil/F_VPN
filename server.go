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
	fmt.Println("(Note: Since we restarted, this key CHANGED. Client verification will fail later, but step 7 works now.)")
	fmt.Println()

	// 2. Слушаем порт
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

		// Обрабатываем подключение
		handleConnection(conn)
	}

	// Чтобы компилятор не ругался
	_ = priv
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Println("\nClient connected:", conn.RemoteAddr())

	// --- ЧТЕНИЕ ПАКЕТА (Client Hello) ---
	// Мы знаем, что пакет должен быть ровно 72 байта
	// [ Time (8) ] + [ ClientPub (32) ] + [ HMAC (32) ]

	buffer := make([]byte, 72)

	// io.ReadFull гарантирует, что мы прочитаем ровно 72 байта или вернем ошибку
	_, err := io.ReadFull(conn, buffer)
	if err != nil {
		fmt.Println("Error reading packet:", err)
		return
	}
	fmt.Println("Received 72 bytes from client.")

	// --- РАЗБОР ПАКЕТА ---
	// Режем колбасу
	payload := buffer[:40]           // Данные (время + ключ)
	receivedSignature := buffer[40:] // Печать клиента

	// --- ПРОВЕРКА HMAC (Фейс-контроль) ---
	// Считаем, какой HMAC должен быть, если пароль PSK верный
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(payload)
	expectedSignature := mac.Sum(nil)

	// Сравниваем полученный и ожидаемый HMAC
	if !hmac.Equal(receivedSignature, expectedSignature) {
		fmt.Println("❌ HMAC VERIFICATION FAILED! (Wrong password or tampered data)")
		return
	}
	fmt.Println("✅ HMAC Valid. Client knows the password.")

	// --- ЧТЕНИЕ ДАННЫХ ---
	// 1. Время
	timestamp := binary.BigEndian.Uint64(payload[:8])
	serverTime := time.Now().Unix()

	fmt.Printf("Client Timestamp: %d (Server Time: %d)\n", timestamp, serverTime)

	// Простейшая проверка времени (чтобы пакет не был из далекого прошлого)
	// Допустим, разница не более 60 секунд
	timeDiff := int64(serverTime) - int64(timestamp)
	if timeDiff > 60 || timeDiff < -60 {
		fmt.Println("⚠️ Timestamp is too old or in future!")
		// return // в реальном коде здесь разрыв соединения
	}

	// 2. Ключ клиента (X25519)
	clientPub := payload[8:40]
	fmt.Printf("Client Ephemeral Key: %x...\n", clientPub[:5])

	fmt.Println("Step 7 Complete: Client packet accepted.")
}
