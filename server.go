package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
)

func main() {
	// создаём ключ подписи сервера
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	fmt.Println("=== SERVER IDENTITY CREATED ===")
	fmt.Println("Server Public Key (save this for client):")
	fmt.Println(hex.EncodeToString(pub))
	fmt.Println()

	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("Server listening on port 9000...")

	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fmt.Println("Client connected:", conn.RemoteAddr())

	// чтобы компилятор не ругался на неиспользуемый ключ
	_ = priv
}
