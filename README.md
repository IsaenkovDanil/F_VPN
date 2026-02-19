# F_VPN v3 (WS+TLS+uTLS+TUN+NAT+Rekey)

Ниже реализован запрошенный апгрейд:

1. `client3.go`: **stdin/stdout убран**, теперь цикл **TUN <-> WSS**.
2. `server3.go`: зеркальный packet loop (**WSS <-> TUN**) + опциональный автозапуск NAT/forward.
3. Протокол вынесен в отдельный пакет `vpn3proto`.
4. Добавлена ротация ключей сессии (каждые N пакетов, с control-frame rekey).
5. Добавлен Cloudflare-friendly режим: порт `443`, проверка `Host`, валидный cert/key.

---

## Что важно понимать

Это уже архитектура VPN-транспорта (VLESS/Trojan-style путь):
- tunnel transport: `WebSocket over TLS`;
- uTLS (клиент маскируется под Chrome Hello);
- fallback HTTP-страница на `/`;
- секретный WS path на `/<uuid-like-path>`;
- PSK auth + replay guard + padding + encryption.

Но это всё ещё **учебный прототип**. Для production нужны: строгий ACL, лимиты, метрики, алерты, fail2ban/WAF policy, rotation policy с подтверждением, hardening CI/CD.

---

## Файлы

- `server3.go` — сервер 443, WS endpoint, TUN, NAT опционально.
- `client3.go` — клиент WS/uTLS, TUN loop.
- `vpn3proto/protocol.go` — общий протокол.
- `vpn3proto/protocol_test.go` — unit тесты.

---

## Можно ли проверять `server.go/server3.go` в WSL2?

Да, **можно**. Для дев-сценария WSL2 отлично подходит.

- Проверка серверной логики на WSL2 валидна.
- Боевой запуск на VPS — Linux.
- Для TUN/NAT в WSL2 нужен root и корректные сетевые настройки WSL2.

---

## Быстрый запуск (Linux/WSL2)

## 1) Подготовь сертификат (локально)

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout dev.key -out dev.crt -days 365 \
  -subj "/CN=your-domain.example"
```

## 2) Сервер: поднять TUN + NAT + WSS

```bash
sudo go run server3.go \
  -addr :443 \
  -ws-path /my-vpn-uuid \
  -psk 'change-this-very-long-psk' \
  -cert ./dev.crt \
  -key ./dev.key \
  -expected-host your-domain.example \
  -tun-name vpn3s \
  -max-padding 120 \
  -rotate-every 500 \
  -auto-nat \
  -out-iface eth0 \
  -tun-cidr 10.66.0.0/24
```

После старта назначь IP серверному TUN:

```bash
sudo ip addr add 10.66.0.1/24 dev vpn3s
sudo ip link set vpn3s up
```

## 3) Клиент: TUN + WSS

```bash
sudo go run client3.go \
  -url wss://your-domain.example/my-vpn-uuid \
  -psk 'change-this-very-long-psk' \
  -tun-name vpn3c \
  -max-padding 120 \
  -rotate-every 500
```

Назначь IP клиентскому TUN и маршрут:

```bash
sudo ip addr add 10.66.0.2/24 dev vpn3c
sudo ip link set vpn3c up
sudo ip route add default via 10.66.0.1 dev vpn3c
```

Проверка:

```bash
curl https://ifconfig.me
```

---

## Подробно для Windows

### Вариант A (рекомендуется): Windows + WSL2 Ubuntu

1. Установи WSL2:

```powershell
wsl --install
```

2. В WSL2:

```bash
sudo apt update
sudo apt install -y golang-go openssl iproute2 iptables curl
```

3. Запуск делай по Linux шагам выше (в WSL2).

4. Вопрос «можно ли проверять server.go в WSL2?» — **да, можно**.

### Вариант B: полностью нативный Windows

В этом варианте текущий `client3.go/server3.go` с `water` ориентирован на Linux/Unix TUN.
Для нативного Windows TUN нужен отдельный вариант на Wintun (как у тебя в старых файлах), поэтому практичнее использовать **WSL2**.

---

## Cloudflare + валидный cert на 443 (боевой контур)

1. DNS:
- `A your-domain.example -> VPS IP`
- В Cloudflare включить proxied (оранжевое облако).

2. Сервер:
- запусти на `:443`;
- укажи `-expected-host your-domain.example`;
- сертификат:
  - либо Let's Encrypt на origin,
  - либо Cloudflare Origin Certificate (`cert.pem/key.pem`).

3. Клиент:
- подключайся только на домен: `wss://your-domain.example/my-vpn-uuid`.

4. Маскировка:
- на `GET /` сервер отдаёт обычную веб-страницу.
- VPN работает только на секретном пути + валидном auth.

---

## Тесты

```bash
go test ./vpn3proto -v
```

---

## Безопасность (обязательно)

- Не используй короткий PSK.
- Меняй WS path на случайный UUID-like.
- Включи rate-limit на уровне Cloudflare/WAF.
- Логи без чувствительных данных.
- Для production добавь ротацию PSK/сертификата по расписанию.
