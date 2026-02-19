package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	utls "github.com/refraction-networking/utls"
)

func main() {
	serverURL := flag.String("url", "wss://127.0.0.1:8443/my-vpn-uuid", "wss URL")
	psk := flag.String("psk", "change-me-super-secret", "pre-shared key")
	insecure := flag.Bool("insecure", false, "skip TLS cert verification")
	caFile := flag.String("ca", "", "custom root CA pem")
	maxPadding := flag.Int("max-padding", 100, "max random padding bytes")
	flag.Parse()

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatal(err)
	}

	dialer := websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 10 * time.Second,
		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			tcpConn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			cfg := &utls.Config{ServerName: host, InsecureSkipVerify: *insecure}
			if *caFile != "" {
				pool := x509.NewCertPool()
				pemData, err := os.ReadFile(*caFile)
				if err != nil {
					_ = tcpConn.Close()
					return nil, err
				}
				if !pool.AppendCertsFromPEM(pemData) {
					_ = tcpConn.Close()
					return nil, fmt.Errorf("failed to parse ca file")
				}
				cfg.RootCAs = pool
			}

			uConn := utls.UClient(tcpConn, cfg, utls.HelloChrome_Auto)
			if err := uConn.HandshakeContext(ctx); err != nil {
				_ = tcpConn.Close()
				return nil, err
			}
			return uConn, nil
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
	}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		log.Fatal(err)
	}
	auth, err := buildAuthMessage(*psk, u.Path, time.Now().Unix(), nonce)
	if err != nil {
		log.Fatal(err)
	}
	authRaw, _ := json.Marshal(auth)
	if err := conn.WriteMessage(websocket.TextMessage, authRaw); err != nil {
		log.Fatal(err)
	}
	_, ack, err := conn.ReadMessage()
	if err != nil {
		log.Fatal(err)
	}
	if string(ack) != "ok" {
		log.Fatalf("server rejected auth: %s", string(ack))
	}
	key, err := deriveSessionKey(*psk, nonce, auth.Timestamp)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("connected. type messages and press Enter.")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" {
			return
		}

		padded, err := addPadding([]byte(line), *maxPadding)
		if err != nil {
			log.Fatal(err)
		}
		enc, err := encryptFrame(key, padded)
		if err != nil {
			log.Fatal(err)
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, enc); err != nil {
			log.Fatal(err)
		}
		_, resp, err := conn.ReadMessage()
		if err != nil {
			log.Fatal(err)
		}
		plainPad, err := decryptFrame(key, resp)
		if err != nil {
			log.Fatal(err)
		}
		plain, err := removePadding(plainPad)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(plain))
	}
}
