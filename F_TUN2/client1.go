package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"golang.zx2c4.com/wintun"
)

func main() {
	// --- 1. НАСТРОЙКА TUN (Как в Этапе 1) ---
	adapter, err := wintun.CreateAdapter("MyVPN", "Example", nil)
	if err != nil {
		log.Fatalf("Ошибка создания адаптера: %v", err)
	}
	defer adapter.Close()

	fmt.Println("✅ CLIENT: Адаптер создан. Жду 5 секунд...")
	fmt.Println("❗ ВНИМАНИЕ: Если ты еще не настроил IP, сделай это сейчас в другом окне!")
	fmt.Println("   Команда: netsh interface ip set address name=\"MyVPN\" source=static addr=10.1.0.2 mask=255.255.255.0 gateway=none")

	time.Sleep(5 * time.Second) // Даем время Windows очухаться

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		log.Fatalf("Ошибка сессии: %v", err)
	}
	defer session.End()

	fmt.Println("✅ CLIENT: TUN запущен!")

	// --- 2. ПОДКЛЮЧЕНИЕ К СЕРВЕРУ ---
	serverAddr := "127.0.0.1:9000" // Локальный сервер
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		log.Fatalf("Не могу подключиться к серверу: %v", err)
	}
	defer conn.Close()
	fmt.Println("✅ CLIENT: Подключились к серверу TCP!")

	// --- 3. ЗАПУСК НАСОСА (TUN -> TCP) ---
	// Читаем пакеты из Windows и шлем на сервер

	packet := make([]byte, 2000) // Буфер

	for {
		// А. Читаем из TUN
		data, err := session.ReceivePacket()
		if err != nil {
			// Игнорируем мелкие ошибки драйвера
			continue
		}

		// Б. Копируем данные (драйвер перезаписывает память, надо сохранить)
		n := len(data)
		copy(packet, data)

		// Освобождаем память драйвера
		session.ReleaseReceivePacket(data)

		// В. Отправляем в TCP (на сервер)
		_, err = conn.Write(packet[:n])
		if err != nil {
			fmt.Println("Ошибка отправки на сервер:", err)
			break
		}

		fmt.Printf("📤 Отправил на сервер %d байт\n", n)
	}
}
