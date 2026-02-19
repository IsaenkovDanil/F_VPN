package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type replayGuard struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	limit int
}

func newReplayGuard(limit int) *replayGuard {
	return &replayGuard{seen: make(map[string]time.Time), limit: limit}
}

func (r *replayGuard) add(nonce string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.seen[nonce]; exists {
		return false
	}
	r.seen[nonce] = now
	if len(r.seen) > r.limit {
		for k, t := range r.seen {
			if now.Sub(t) > 3*time.Minute {
				delete(r.seen, k)
			}
		}
	}
	return true
}

func main() {
	addr := flag.String("addr", ":8443", "HTTPS bind address")
	wsPath := flag.String("ws-path", "/my-vpn-uuid", "secret websocket path")
	psk := flag.String("psk", "change-me-super-secret", "pre-shared key")
	cert := flag.String("cert", "", "TLS cert PEM path")
	key := flag.String("key", "", "TLS key PEM path")
	coverFile := flag.String("cover-file", "", "optional HTML file for fallback page")
	maxPadding := flag.Int("max-padding", 100, "max random padding bytes")
	flag.Parse()

	if *cert == "" || *key == "" {
		log.Fatal("-cert and -key are required")
	}

	coverPage := []byte("<html><body><h1>Welcome</h1><p>Nothing special here.</p></body></html>")
	if *coverFile != "" {
		b, err := os.ReadFile(*coverFile)
		if err != nil {
			log.Fatalf("read cover-file: %v", err)
		}
		coverPage = b
	}

	guard := newReplayGuard(5000)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(coverPage)
	})

	mux.HandleFunc(*wsPath, func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		_, authRaw, err := conn.ReadMessage()
		if err != nil {
			return
		}

		var auth authMessage
		if err := json.Unmarshal(authRaw, &auth); err != nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("bad auth"))
			return
		}

		nonce, err := verifyAuthMessage(*psk, *wsPath, auth, time.Now())
		if err != nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("auth failed"))
			return
		}
		if !guard.add(auth.Nonce, time.Now()) {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("replay detected"))
			return
		}

		key, err := deriveSessionKey(*psk, nonce, auth.Timestamp)
		if err != nil {
			return
		}

		_ = conn.WriteMessage(websocket.TextMessage, []byte("ok"))
		_ = conn.SetReadDeadline(time.Time{})
		log.Printf("vpn session established from %s", r.RemoteAddr)

		for {
			mt, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			plainPadded, err := decryptFrame(key, payload)
			if err != nil {
				return
			}
			plain, err := removePadding(plainPadded)
			if err != nil {
				return
			}

			response := []byte("echo:" + string(plain))
			respPadded, err := addPadding(response, *maxPadding)
			if err != nil {
				return
			}
			enc, err := encryptFrame(key, respPadded)
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
				return
			}
		}
	})

	s := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Printf("server3 listening on https://0.0.0.0%s (WS path %s)\n", *addr, *wsPath)
	log.Fatal(s.ListenAndServeTLS(*cert, *key))
}
