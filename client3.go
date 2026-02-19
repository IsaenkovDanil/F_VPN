package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"f_vpn/vpn3proto"
	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
	"github.com/songgao/water"
)

type trafficState struct {
	mu      sync.Mutex
	baseKey []byte
	sendGen uint32
	recvGen uint32
	sendKey []byte
	recvKey []byte
}

func newTrafficState(base []byte) *trafficState {
	return &trafficState{baseKey: base, sendKey: vpn3proto.DeriveTrafficKey(base, 0, "c2s"), recvKey: vpn3proto.DeriveTrafficKey(base, 0, "s2c")}
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
	t.sendKey = vpn3proto.DeriveTrafficKey(t.baseKey, t.sendGen, "c2s")
}
func (t *trafficState) applyRecv(next uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recvGen = next
	t.recvKey = vpn3proto.DeriveTrafficKey(t.baseKey, t.recvGen, "s2c")
}

func main() {
	serverURL := flag.String("url", "wss://127.0.0.1:443/my-vpn-uuid", "wss URL")
	psk := flag.String("psk", "change-me-super-secret", "pre-shared key")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification")
	caFile := flag.String("ca", "", "custom root CA pem")
	tunName := flag.String("tun-name", "vpn3c", "client tun name")
	maxPadding := flag.Int("max-padding", 100, "max random padding bytes")
	rotateEvery := flag.Uint("rotate-every", 500, "rotate traffic key every N packets per direction")
	flag.Parse()

	tun, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: *tunName}})
	if err != nil {
		log.Fatalf("tun create: %v", err)
	}
	log.Printf("TUN interface created: %s", tun.Name())
	log.Printf("Configure TUN IP manually, e.g.: ip addr add 10.66.0.2/24 dev %s && ip link set %s up", tun.Name(), tun.Name())

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatal(err)
	}
	dialer := websocket.Dialer{Proxy: http.ProxyFromEnvironment, HandshakeTimeout: 10 * time.Second, NetDialTLSContext: utlsDialer(*insecure, *caFile), TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure}}
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	auth, err := vpn3proto.BuildAuthMessage(*psk, u.Path, time.Now().Unix(), nonce)
	if err != nil {
		log.Fatal(err)
	}
	authRaw, _ := json.Marshal(auth)
	if err := conn.WriteMessage(websocket.TextMessage, authRaw); err != nil {
		log.Fatal(err)
	}
	_, ack, err := conn.ReadMessage()
	if err != nil || string(ack) != "ok" {
		log.Fatalf("auth rejected: %v %s", err, string(ack))
	}
	state := newTrafficState(vpn3proto.DeriveBaseKey(*psk, nonce, auth.Timestamp))

	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := make([]byte, 2000)
		var sent uint64
		for {
			n, err := tun.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if *rotateEvery > 0 && sent > 0 && sent%uint64(*rotateEvery) == 0 {
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
			data := vpn3proto.MakeDataFrame(buf[:n])
			padded, _ := vpn3proto.AddPadding(data, *maxPadding)
			enc, _ := vpn3proto.EncryptFrame(state.getSendKey(), padded)
			if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
				errCh <- err
				return
			}
			sent++
		}
	}()

	go func() {
		defer wg.Done()
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
			case vpn3proto.FrameRekey:
				if len(body) == 4 {
					state.applyRecv(binary.BigEndian.Uint32(body))
				}
			}
		}
	}()

	log.Println("VPN tunnel started (TUN <-> WSS)")
	log.Printf("Client routing hint: ip route add default via 10.66.0.1 dev %s", tun.Name())
	log.Printf("Windows WSL2 hint: use `route add`/`netsh interface ipv4` equivalents")

	err := <-errCh
	log.Printf("stopped: %v", err)
	_ = conn.Close()
	wg.Wait()
}

func utlsDialer(insecure bool, caFile string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		tcpConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		cfg := &utls.Config{ServerName: host, InsecureSkipVerify: insecure}
		if caFile != "" {
			pool := x509.NewCertPool()
			pemData, err := os.ReadFile(caFile)
			if err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			if !pool.AppendCertsFromPEM(pemData) {
				_ = tcpConn.Close()
				return nil, errors.New("failed to parse ca file")
			}
			cfg.RootCAs = pool
		}
		uConn := utls.UClient(tcpConn, cfg, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			_ = tcpConn.Close()
			return nil, err
		}
		return uConn, nil
	}
}
