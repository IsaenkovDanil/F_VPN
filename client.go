package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net"
)

// вставь сюда public key сервера
const serverPublicKeyHex = "941fc05b2a99f5f23ab83e10a0b2f4918c0a93cef4ff0ff00fa1ec180579b091"

func main() {
	// преобразуем hex строку в байты
	pubBytes, err := hex.DecodeString(serverPublicKeyHex)
	if err != nil {
		panic(err)
	}

	// создаём ed25519 ключ
	serverPubKey := ed25519.PublicKey(pubBytes)

	fmt.Println("Loaded server public key:")
	fmt.Println(serverPubKey)

	conn, err := net.Dial("tcp", "127.0.0.1:9000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Connected to server")
}
