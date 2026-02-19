package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"f_vpn/vpn3proto"
	"github.com/gorilla/websocket"
	"github.com/songgao/water"
)

type replayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (r *replayGuard) add(nonce string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.seen[nonce]; ok {
		return false
	}
	r.seen[nonce] = now
	for n, t := range r.seen {
		if now.Sub(t) > 3*time.Minute {
			delete(r.seen, n)
		}
	}
	return true
}

type trafficState struct {
	mu      sync.Mutex
	baseKey []byte
	sendGen uint32
	recvGen uint32
	sendKey []byte
	recvKey []byte
}

func newTrafficState(base []byte) *trafficState {
	return &trafficState{
		baseKey: base,
		sendKey: vpn3proto.DeriveTrafficKey(base, 0, "s2c"),
		recvKey: vpn3proto.DeriveTrafficKey(base, 0, "c2s"),
	}
}

func (t *trafficState) getSendKey() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.sendKey...)
}
func (t *trafficState) getRecvKey() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.recvKey...)
}

func (t *trafficState) nextSendGen() uint32 { t.mu.Lock(); defer t.mu.Unlock(); return t.sendGen + 1 }
func (t *trafficState) applySend(next uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sendGen = next
	t.sendKey = vpn3proto.DeriveTrafficKey(t.baseKey, t.sendGen, "s2c")
}

func (t *trafficState) applyRecv(next uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recvGen = next
	t.recvKey = vpn3proto.DeriveTrafficKey(t.baseKey, t.recvGen, "c2s")
}

func main() {
	addr := flag.String("addr", ":443", "HTTPS bind address")
	wsPath := flag.String("ws-path", "/my-vpn-uuid", "secret websocket path")
	psk := flag.String("psk", "change-me-super-secret", "pre-shared key")
	cert := flag.String("cert", "", "TLS cert PEM path")
	key := flag.String("key", "", "TLS key PEM path")
	expectedHost := flag.String("expected-host", "", "optional expected Host header for Cloudflare front")
	coverFile := flag.String("cover-file", "", "optional HTML file for fallback page")
	tunName := flag.String("tun-name", "vpn3s", "server tun name")
	maxPadding := flag.Int("max-padding", 100, "max random padding bytes")
	rotateEvery := flag.Uint("rotate-every", 500, "rotate traffic key every N packets per direction")
	autoNAT := flag.Bool("auto-nat", false, "enable Linux forwarding + iptables MASQUERADE")
	outIface := flag.String("out-iface", "eth0", "internet iface for MASQUERADE")
	tunCIDR := flag.String("tun-cidr", "10.66.0.0/24", "tun subnet for NAT rule")
	flag.Parse()

	if *cert == "" || *key == "" {
		log.Fatal("-cert and -key are required")
	}
	if *autoNAT {
		if err := enableNAT(*outIface, *tunCIDR); err != nil {
			log.Fatalf("auto-nat failed: %v", err)
		}
	}

	tun, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: *tunName}})
	if err != nil {
		log.Fatalf("tun create: %v", err)
	}
	log.Printf("TUN interface created: %s", tun.Name())
	log.Printf("Configure TUN IP manually, e.g.: ip addr add 10.66.0.1/24 dev %s && ip link set %s up", tun.Name(), tun.Name())

	coverPage := []byte("<html><body><h1>Welcome</h1><p>Static site.</p></body></html>")
	if *coverFile != "" {
		if b, err := os.ReadFile(*coverFile); err == nil {
			coverPage = b
		}
	}

	guard := &replayGuard{seen: map[string]time.Time{}}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	var active int32

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if *expectedHost != "" && r.Host != *expectedHost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(coverPage)
	})

	mux.HandleFunc(*wsPath, func(w http.ResponseWriter, r *http.Request) {
		if *expectedHost != "" && r.Host != *expectedHost {
			http.NotFound(w, r)
			return
		}
		if !atomic.CompareAndSwapInt32(&active, 0, 1) {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		defer atomic.StoreInt32(&active, 0)

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, authRaw, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var auth vpn3proto.AuthMessage
		if err := json.Unmarshal(authRaw, &auth); err != nil {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("bad auth"))
			return
		}
		nonce, err := vpn3proto.VerifyAuthMessage(*psk, *wsPath, auth, time.Now())
		if err != nil || !guard.add(auth.Nonce, time.Now()) {
			_ = conn.WriteMessage(websocket.TextMessage, []byte("auth failed"))
			return
		}
		state := newTrafficState(vpn3proto.DeriveBaseKey(*psk, nonce, auth.Timestamp))
		_ = conn.SetReadDeadline(time.Time{})
		_ = conn.WriteMessage(websocket.TextMessage, []byte("ok"))

		var wg sync.WaitGroup
		errCh := make(chan error, 2)
		wg.Add(2)

		go func() {
			defer wg.Done()
			var recvPackets uint64
			for {
				mt, payload, err := conn.ReadMessage()
				if err != nil {
					errCh <- err
					return
				}
				if mt != websocket.BinaryMessage {
					continue
				}
				plainPadded, err := vpn3proto.DecryptFrame(state.getRecvKey(), payload)
				if err != nil {
					errCh <- err
					return
				}
				plain, err := vpn3proto.RemovePadding(plainPadded)
				if err != nil {
					errCh <- err
					return
				}
				kind, body, err := vpn3proto.ParseFrame(plain)
				if err != nil {
					errCh <- err
					return
				}
				switch kind {
				case vpn3proto.FrameData:
					if _, err := tun.Write(body); err != nil {
						errCh <- err
						return
					}
					recvPackets++
				case vpn3proto.FrameRekey:
					if len(body) != 4 {
						continue
					}
					state.applyRecv(binary.BigEndian.Uint32(body))
				}
			}
		}()

		go func() {
			defer wg.Done()
			buf := make([]byte, 2000)
			var sentPackets uint64
			for {
				n, err := tun.Read(buf)
				if err != nil {
					errCh <- err
					return
				}

				if *rotateEvery > 0 && sentPackets > 0 && sentPackets%uint64(*rotateEvery) == 0 {
					next := state.nextSendGen()
					rf := vpn3proto.MakeRekeyFrame(next, false)
					packed, _ := vpn3proto.AddPadding(rf, *maxPadding)
					enc, _ := vpn3proto.EncryptFrame(state.getSendKey(), packed)
					if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
						errCh <- err
						return
					}
					state.applySend(next)
				}

				frame := vpn3proto.MakeDataFrame(buf[:n])
				padded, _ := vpn3proto.AddPadding(frame, *maxPadding)
				enc, _ := vpn3proto.EncryptFrame(state.getSendKey(), padded)
				if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
					errCh <- err
					return
				}
				sentPackets++
			}
		}()

		select {
		case err := <-errCh:
			log.Printf("session closed: %v", err)
		case <-time.After(24 * time.Hour):
		}
		_ = conn.Close()
		wg.Wait()
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("server3 listening at https://0.0.0.0%s (ws path: %s)", *addr, *wsPath)
	log.Fatal(srv.ListenAndServeTLS(*cert, *key))
}

func enableNAT(outIface, tunCIDR string) error {
	cmds := [][]string{
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"iptables", "-t", "nat", "-C", "POSTROUTING", "-s", tunCIDR, "-o", outIface, "-j", "MASQUERADE"},
	}
	for _, c := range cmds {
		if err := exec.Command(c[0], c[1:]...).Run(); err != nil && c[0] == "iptables" {
			if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", tunCIDR, "-o", outIface, "-j", "MASQUERADE").Run(); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
	}
	fmt.Println("NAT forwarding enabled")
	return nil
}
