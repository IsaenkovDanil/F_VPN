package main

import (
	"fmt"
	"io"
	"net"
)

func main() {
	// 1. Слушаем порт 9000
	listener, err := net.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Println("SERVER: Жду подключения на порту 9000...")

	for {
		// 2. Принимаем клиента
		conn, err := listener.Accept()
		if err != nil {
			continue
		}

		fmt.Println("SERVER: Клиент подключился!", conn.RemoteAddr())

		// Запускаем обработку в отдельном потоке
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()

	// Буфер для чтения (большой, чтобы влез любой пакет)
	buf := make([]byte, 2000)

	for {
		// 3. Читаем данные из TCP (то, что прислал VPN-клиент)
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("SERVER: Ошибка чтения:", err)
			}
			break
		}

		// 4. Просто выводим информацию о пакете
		fmt.Printf("SERVER: Получил пакет из туннеля! Размер: %d байт\n", n)

		// (В будущем здесь мы будем отправлять пакет в интернет)
	}
	fmt.Println("SERVER: Клиент отключился.")
}
