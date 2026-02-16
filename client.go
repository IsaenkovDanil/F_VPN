package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// 1. Публичный ключ сервера (ПАСПОРТ)
// !!! ВСТАВЬ СЮДА ТОТ ЖЕ КЛЮЧ, ЧТО БЫЛ РАНЬШЕ !!!
const serverEdPublicKeyHex = "ВСТАВЬ_СЮДА_КЛЮЧ_СЕРВЕРА_ИЗ_ШАГА_3"

// 2. Наш общий пароль (PSK)
const psk = "MySecretPassword"

func main() {
	// --- ПОДГОТОВКА ---
	serverEdPubBytes, _ := hex.DecodeString(serverEdPublicKeyHex)
	serverEdPubKey := ed25519.PublicKey(serverEdPubBytes)
	fmt.Println("Server Identity Loaded:", serverEdPubKey)

	// --- 1. ГЕНЕРАЦИЯ КЛЮЧЕЙ (X25519) ---
	clientPub, clientPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	// clientPub - это указатель на массив [32]byte
	// clientPriv - это указатель на массив [32]byte

	// --- 2. ПОДКЛЮЧЕНИЕ ---
	conn, err := net.Dial("tcp", "127.0.0.1:9000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	fmt.Println("Connected to server...")

	// --- 3. СБОРКА ПАКЕТА (Client Hello) ---

	// А. ВРЕМЯ (8 байт)
	timestamp := time.Now().Unix() // текущее время
	timeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBuf, uint64(timestamp))

	// Б. PAYLOAD (Время + Публичный Ключ)
	// payload = [ time (8) ] + [ clientPub (32) ]
	payload := append(timeBuf, clientPub[:]...)

	// В. HMAC (Печать PSK)
	// Берем пароль, считаем хеш от payload
	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write(payload)
	signature := mac.Sum(nil) // 32 байта

	// Г. ИТОГОВЫЙ ПАКЕТ
	// packet = [ payload (40) ] + [ signature (32) ]
	packet := append(payload, signature...)

	fmt.Printf("Sending packet (size %d bytes)...\n", len(packet))

	// --- 4. ОТПРАВКА ---
	_, err = conn.Write(packet)
	if err != nil {
		panic(err)
	}

	fmt.Println("Client Hello SENT! Waiting for response...")

	// Держим соединение открытым, пока не придумаем, что делать дальше
	// (в следующих шагах мы будем здесь читать ответ)
	time.Sleep(10 * time.Second)

	// Чтобы компилятор не ругался
	_ = clientPriv
}
