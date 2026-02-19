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

	"sync" // ДЛЯ ГОРУТИН

	"golang.org/x/crypto/chacha20poly1305" // ДЛЯ ШИФРОВАНИЯ
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"

	"os/exec" // ДОБАВИТЬ ЭТО (для настройки IP)

	"github.com/songgao/water" // ДОБАВИТЬ ЭТО (вместо wintun)
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

	// --- ФИНАЛЬНЫЙ ШАГ: ВЫЧИСЛЕНИЕ КЛЮЧЕЙ (ECDH) ---

	// Магия Диффи-Хеллмана:
	// СЕРВЕР берет: СВОЙ Секрет + ПУБЛИЧНЫЙ Ключ Клиента
	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, serverPriv, &clientPubArr)

	// HKDF: Создаем те же ключи
	hash := sha256.New
	kdf := hkdf.New(hash, sharedSecret[:], nil, nil)

	// ВАЖНО: Порядок должен быть таким же, как у клиента
	keyClientToServer := make([]byte, 32)
	keyServerToClient := make([]byte, 32)

	io.ReadFull(kdf, keyClientToServer)
	io.ReadFull(kdf, keyServerToClient)

	fmt.Println("\n🎉 SERVER HANDSHAKE COMPLETE!")
	fmt.Printf("🔑 Key Client->Server: %x\n", keyClientToServer)
	fmt.Printf("🔑 Key Server->Client: %x\n", keyServerToClient)

	// ==========================================
	// ЭТАП: ОБРАБОТКА ЗАШИФРОВАННОГО ТРАФИКА
	// ==========================================

	// Создаем шифровальщики (ВНИМАНИЕ: Ключи наоборот по сравнению с клиентом!)
	// Сервер ЧИТАЕТ ключом Client->Server
	aeadReader, err := chacha20poly1305.New(keyClientToServer)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Сервер ПИШЕТ ключом Server->Client (если будем отвечать)
	aeadWriter, err := chacha20poly1305.New(keyServerToClient)
	if err != nil {
		fmt.Println(err)
		return
	}

	// ==========================================
	// ЭТАП 6: НАСТРОЙКА TUN (LINUX ВЕРСИЯ)
	// ==========================================

	// 1. Создаем интерфейс
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "tun0" // Назовем интерфейс tun0

	ifce, err := water.New(config)
	if err != nil {
		fmt.Println("❌ Ошибка создания TUN:", err)
		return
	}
	defer ifce.Close()

	fmt.Println("✅ Linux TUN created: tun0")

	// 2. Настраиваем IP адрес через командную строку Linux
	// Аналог netsh в Windows: ip addr add 10.1.0.1/24 dev tun0 && ip link set dev tun0 up
	cmd := exec.Command("ip", "addr", "add", "10.1.0.1/24", "dev", "tun0")
	if err := cmd.Run(); err != nil {
		fmt.Println("❌ Ошибка настройки IP:", err)
		// Не выходим, вдруг уже настроено
	}

	cmdUp := exec.Command("ip", "link", "set", "dev", "tun0", "up")
	if err := cmdUp.Run(); err != nil {
		fmt.Println("❌ Ошибка поднятия интерфейса:", err)
		return
	}

	fmt.Println("🚀 Interface UP! IP 10.1.0.1 set.")

	// ==========================================
	// ЭТАП 7: ЗАПУСК ДВУХ ГОРУТИН (ЧТЕНИЕ И ЗАПИСЬ)
	// ==========================================
	var wg sync.WaitGroup
	wg.Add(2)

	// ГОЛУБЬ 1: TCP (от клиента) -> TUN (в систему сервера)
	// Сервер получает шифрованный пакет, расшифровывает и отдает Windows
	go func() {
		defer wg.Done()

		// Буфер для длины
		headerBuf := make([]byte, 2)

		fmt.Println("🚀 Tunnel established! Waiting for packets...")

		for {
			// 1. Читаем длину (2 байта)
			_, err := io.ReadFull(conn, headerBuf)
			if err != nil {
				fmt.Println("Client disconnected:", err)
				return
			}
			length := binary.BigEndian.Uint16(headerBuf)

			// 2. Читаем зашифрованные данные
			encryptedData := make([]byte, length)
			_, err = io.ReadFull(conn, encryptedData)
			if err != nil {
				return
			}

			// 3. Разделяем Nonce и Ciphertext
			if len(encryptedData) < chacha20poly1305.NonceSize {
				continue
			}
			nonce := encryptedData[:chacha20poly1305.NonceSize]
			ciphertext := encryptedData[chacha20poly1305.NonceSize:]

			decrypted, err := aeadReader.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				fmt.Println("❌ Decryption failed!")
				continue
			}

			// Г. Пишем в TUN (Linux)
			_, err = ifce.Write(decrypted) // Просто пишем байты как в файл
			if err != nil {
				fmt.Println("TUN Write error:", err)
			}
		}
	}()

	// ГОЛУБЬ 2: TUN (от системы сервера) -> TCP (к клиенту)
	// Сервер видит ответ (например, от своего ping), шифрует и шлет клиенту
	go func() {
		defer wg.Done()
		packet := make([]byte, 2000) // Буфер для чтения из TUN
		nonce := make([]byte, chacha20poly1305.NonceSize)

		for {
			// А. Читаем из TUN (Windows хочет отправить ответ на 10.1.0.2)
			packet := make([]byte, 2000) // Буфер
			nonce := make([]byte, chacha20poly1305.NonceSize)

			for {
				// А. Читаем из TUN (Linux)
				n, err := ifce.Read(packet) // Читаем как из файла
				if err != nil {
					fmt.Println("TUN Read error:", err)
					break
				}

				// Б. Шифруем (packet[:n] - это данные)
				if _, err := rand.Read(nonce); err != nil {
					return
				}
				encrypted := aeadWriter.Seal(nonce, nonce, packet[:n], nil)

				// В. Готовим пакет [Длина] + [Encrypted]
				finalPkg := make([]byte, 2+len(encrypted))
				binary.BigEndian.PutUint16(finalPkg[:2], uint16(len(encrypted)))
				copy(finalPkg[2:], encrypted)

				// Г. Отправляем клиенту
				_, err = conn.Write(finalPkg)
				if err != nil {
					return
				}
			}
		}
	}()

	wg.Wait()

}
