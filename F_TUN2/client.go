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

	"log"
	"sync" // ДЛЯ ГОРУТИН

	"golang.org/x/crypto/chacha20poly1305" // ДЛЯ ШИФРОВАНИЯ
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.zx2c4.com/wintun" // ДЛЯ TUN (только в client.go)
)

// 1. ПУБЛИЧНЫЙ КЛЮЧ СЕРВЕРА (ПАСПОРТ)
// !!! ЗАПУСТИ SERVER.GO, СКОПИРУЙ КЛЮЧ И ВСТАВЬ СЮДА !!!
const serverEdPublicKeyHex = "6666935bb141b6b6caaaa648827314d90e06e25704007002050384bf0a2f6bc5"

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

	// ==========================================
	// ЭТАП 2: НАСТРОЙКА TUN (ИЗ client1.go)
	// ==========================================

	// 1. Создаем шифровальщики
	aeadWriter, err := chacha20poly1305.New(keyWriter) // Для отправки
	if err != nil {
		panic(err)
	}
	aeadReader, err := chacha20poly1305.New(keyReader) // Для приема
	if err != nil {
		panic(err)
	}

	// 2. Поднимаем TUN
	adapter, err := wintun.CreateAdapter("MyVPN", "Example", nil)
	if err != nil {
		log.Fatalf("Ошибка создания адаптера: %v", err)
	}
	defer adapter.Close()

	fmt.Println("✅ TUN Created. Setting IP 10.1.0.2...")
	// Тут можно программно вызвать netsh или оставить ручную настройку, как у тебя было

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		panic(err)
	}
	defer session.End()

	// ==========================================
	// ЭТАП 3: ЗАПУСК ПЕРЕДАЧИ ДАННЫХ
	// ==========================================
	var wg sync.WaitGroup
	wg.Add(2)

	// ГОЛУБЬ 1: TUN -> ШИФРОВАНИЕ -> TCP (Отправка на сервер)
	go func() {
		defer wg.Done()
		packet := make([]byte, 2000)                      // Сырой пакет
		nonce := make([]byte, chacha20poly1305.NonceSize) // 12 байт

		for {
			// А. Читаем из TUN
			data, err := session.ReceivePacket()
			if err != nil {
				continue
			}
			copy(packet, data)
			pktLen := len(data)
			session.ReleaseReceivePacket(data)

			// Б. Генерируем случайный Nonce (важно для безопасности!)
			if _, err := rand.Read(nonce); err != nil {
				fmt.Println("Nonce error:", err)
				return
			}

			// В. Шифруем (Seal добавляет данные к nonce)
			// encrypted = [Nonce] + [Ciphertext + Tag]
			encrypted := aeadWriter.Seal(nonce, nonce, packet[:pktLen], nil)

			// Г. Формируем фрейм для TCP: [Длина (2 байта)] + [Encrypted]
			finalPkg := make([]byte, 2+len(encrypted))
			binary.BigEndian.PutUint16(finalPkg[:2], uint16(len(encrypted)))
			copy(finalPkg[2:], encrypted)

			// Д. Отправляем в TCP
			_, err = conn.Write(finalPkg)
			if err != nil {
				fmt.Println("TCP Write error:", err)
				return
			}
			fmt.Printf("⬆ Sent %d encrypted bytes\n", len(finalPkg))
		}
	}()

	// ГОЛУБЬ 2: TCP -> РАСШИФРОВКА -> TUN (Прием от сервера)
	go func() {
		defer wg.Done()
		header := make([]byte, 2) // Для чтения длины

		for {
			// А. Читаем длину пакета (2 байта)
			_, err := io.ReadFull(conn, header)
			if err != nil {
				fmt.Println("TCP Read error:", err)
				return
			}
			length := binary.BigEndian.Uint16(header)

			// Б. Читаем тело пакета
			encryptedPkt := make([]byte, length)
			_, err = io.ReadFull(conn, encryptedPkt)
			if err != nil {
				fmt.Println("TCP Body read error:", err)
				return
			}

			// В. Расшифровываем
			// Первые 12 байт - это Nonce, остальное - шифротекст
			if len(encryptedPkt) < chacha20poly1305.NonceSize {
				continue
			}
			nonce := encryptedPkt[:chacha20poly1305.NonceSize]
			ciphertext := encryptedPkt[chacha20poly1305.NonceSize:]

			decrypted, err := aeadReader.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				fmt.Println("⛔ Decrypt failed (bad key or fake packet)!")
				continue
			}

			// Г. Пишем в TUN (Windows увидит пакет)
			packet, err := session.AllocateSendPacket(len(decrypted))
			if err == nil {
				copy(packet, decrypted)
				session.SendPacket(packet)
				fmt.Printf("⬇ Received & Decrypted %d bytes\n", len(decrypted))
			}
		}
	}()

	wg.Wait()

}
