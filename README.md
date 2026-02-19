# F_VPN: server3/client3 (WebSocket + TLS + padding + probe-resistance)

Этот README описывает новый учебный контур `server3.go` + `client3.go`:

- транспорт: **WebSocket over TLS (wss://)**;
- маскировка: сервер отвечает обычной HTML-страницей на `/`;
- доступ к VPN-каналу только на секретном WebSocket пути (например `/my-vpn-uuid`);
- авторизация по PSK + HMAC + timestamp + nonce;
- защита от replay (повтор nonce);
- шифрование полезной нагрузки: AES-256-GCM;
- padding (случайный мусор до `max-padding` байт в кадре).

> Важно: это учебная реализация уровня «прототип архитектуры». Здесь нет полноценного TUN forwarding. Сейчас клиент отправляет сообщения из stdin, сервер делает encrypted echo. Это база для следующего шага: подмена stdin на чтение/запись TUN.

---

## 1) Что добавлено

- `server3.go` — HTTPS сервер + WebSocket endpoint + fallback page + auth + replay guard + encrypted echo.
- `client3.go` — WSS клиент на `gorilla/websocket` + uTLS ClientHello (Chrome mimic) + auth + encrypted exchange.
- `vpn3_protocol.go` — общее протокольное ядро (auth, key derivation, padding, encrypt/decrypt).
- `vpn3_protocol_test.go` — базовые тесты для auth/padding/crypto.

---

## 2) Можно ли проверять `server.go`/`server3.go` только на Linux или в Windows WSL2 тоже?

Коротко: **WSL2 тоже можно и это нормальный вариант**.

- Для серверной части (`server.go`, `server3.go`) Linux и WSL2 практически одинаковы с точки зрения сети/Go.
- Для production VPS всё равно целевой сценарий — Linux.
- Для локальной разработки на Windows оптимально:
  - сервер запускать в **WSL2 Ubuntu**,
  - клиент можно запускать и в WSL2, и в PowerShell (при наличии Go и зависимостей).

Если используешь TUN-часть в будущем:
- Linux TUN проще поднимать в Linux/WSL2.
- Нативный Windows TUN требует отдельной работы с Wintun и правами администратора.

---

## 3) Быстрый запуск на Linux/WSL2

## 3.1 Подготовка TLS сертификата для локального теста

В каталоге проекта:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev.key -out dev.crt -days 365 \
  -subj "/CN=127.0.0.1"
```

## 3.2 Запуск сервера

```bash
go run server3.go vpn3_protocol.go \
  -addr :8443 \
  -ws-path /my-vpn-uuid \
  -psk 'strong-dev-psk' \
  -cert ./dev.crt \
  -key ./dev.key \
  -max-padding 100
```

Проверка fallback страницы:

```bash
curl -k https://127.0.0.1:8443/
```

## 3.3 Запуск клиента

```bash
go run client3.go vpn3_protocol.go \
  -url wss://127.0.0.1:8443/my-vpn-uuid \
  -psk 'strong-dev-psk' \
  -insecure
```

Введи текст и нажми Enter, должен прийти ответ `echo:<текст>`.

---

## 4) Подробные инструкции для Windows

Ниже 2 рабочих варианта.

## Вариант A (рекомендуется): Windows + WSL2 (Ubuntu)

### Шаг 1. Установи WSL2

В PowerShell (Admin):

```powershell
wsl --install
```

Перезагрузка, затем настрой Ubuntu.

### Шаг 2. Установи Go в WSL2

В Ubuntu:

```bash
sudo apt update
sudo apt install -y golang-go openssl ca-certificates
```

Проверка:

```bash
go version
```

### Шаг 3. Перейди в проект

Если проект на диске C:

```bash
cd /mnt/c/path/to/F_VPN
```

Или клонируй проект прямо в Linux FS (`~/projects/F_VPN`) — обычно быстрее по IO.

### Шаг 4. Сгенерируй dev-сертификат

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev.key -out dev.crt -days 365 \
  -subj "/CN=127.0.0.1"
```

### Шаг 5. Запусти сервер

```bash
go run server3.go vpn3_protocol.go -addr :8443 -ws-path /my-vpn-uuid -psk 'strong-dev-psk' -cert ./dev.crt -key ./dev.key
```

### Шаг 6. Запусти клиент (в другом окне WSL2)

```bash
go run client3.go vpn3_protocol.go -url wss://127.0.0.1:8443/my-vpn-uuid -psk 'strong-dev-psk' -insecure
```

### Шаг 7. Smoke test

- В клиенте набери `hello`.
- Ожидай `echo:hello`.

---

## Вариант B: Полностью в Windows (PowerShell)

### Шаг 1. Установи Go for Windows

- Скачай installer с официального сайта Go.
- Убедись, что `go version` работает в PowerShell.

### Шаг 2. Установи OpenSSL (один из вариантов)

- Git for Windows (в составе есть openssl), или
- отдельный OpenSSL installer.

### Шаг 3. Сгенерируй сертификат

В PowerShell (пример с OpenSSL в PATH):

```powershell
openssl req -x509 -newkey rsa:2048 -nodes `
  -keyout dev.key -out dev.crt -days 365 `
  -subj "/CN=127.0.0.1"
```

### Шаг 4. Запусти сервер

```powershell
go run .\server3.go .\vpn3_protocol.go -addr :8443 -ws-path /my-vpn-uuid -psk "strong-dev-psk" -cert .\dev.crt -key .\dev.key
```

### Шаг 5. Запусти клиент

```powershell
go run .\client3.go .\vpn3_protocol.go -url wss://127.0.0.1:8443/my-vpn-uuid -psk "strong-dev-psk" -insecure
```

---

## 5) Тесты

Запуск unit-тестов протокольного ядра:

```bash
go test vpn3_protocol_test.go vpn3_protocol.go -v
```

---

## 6) Переход к реальному VPN дальше

Следующий шаг (после стабилизации `server3/client3`):

1. заменить stdin/stdout в `client3.go` на TUN read/write;
2. сделать зеркальный packet loop на `server3.go` и маршрутизацию в интернет (NAT/forward);
3. вынести протокол в отдельный пакет;
4. добавить ротацию ключей сессии;
5. добавить доменный фронт через Cloudflare и валидный cert на 443.

---

## 7) Важные замечания по безопасности

- Не используй `-insecure` в production.
- PSK должен быть длинным случайным значением (32+ байта).
- Секретный путь должен быть непредсказуемым (`/uuid-like-random-path`).
- Нужен rate-limit на HTTP уровне (Nginx/Caddy/Cloudflare rules).
- Для боевого режима обязательно логировать минимум данных.
