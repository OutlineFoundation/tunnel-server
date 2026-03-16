// Copyright 2022 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/Jigsaw-Code/outline-ss-server/service"
	"github.com/Jigsaw-Code/outline-ss-server/service/metrics"
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	testSecret = "secret"
)

func TestParseAccessKey(t *testing.T) {
	testCases := []struct {
		name    string
		key     string
		want    sessionConfig
		wantErr bool
	}{
		{
			name: "with b64 padding",
			key:  "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA==@127.0.0.1:9000/",
			want: sessionConfig{host: "127.0.0.1", port: 9000, cipher: "chacha20-ietf-poly1305", secret: "password"},
		},
		{
			name: "without b64 padding",
			key:  "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8080",
			want: sessionConfig{host: "1.2.3.4", port: 8080, cipher: "chacha20-ietf-poly1305", secret: "password"},
		},
		{
			name: "without b64",
			key:  "ss://chacha20-ietf-poly1305:password@1.2.3.4:9000/",
			want: sessionConfig{host: "1.2.3.4", port: 9000, cipher: "chacha20-ietf-poly1305", secret: "password"},
		},
		{
			name: "with tag",
			key:  "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8080#TAG",
			want: sessionConfig{host: "1.2.3.4", port: 8080, cipher: "chacha20-ietf-poly1305", secret: "password"},
		},
		{
			name:    "fail on no secret",
			key:     "ss://1.2.3.4:8080",
			wantErr: true,
		},
		{
			name:    "fail on no port",
			key:     "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4#TAG",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAccessKey(tc.key)
			if err != nil {
				if !tc.wantErr {
					t.Errorf("parseKey('%s') got unexpected error: %v", tc.key, err)
				}
			} else if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseKey('%s') got=%v want=%v", tc.key, got, tc.want)
			}
		})
	}
}

func TestSocksToSS(t *testing.T) {
	ssSrvListener, ssSrv := startSSServer(t)
	defer ssSrv.Stop()

	echoListener, echoCloseCh := startEchoServer(t)
	defer echoListener.Close()

	ssCli, err := RunSocksToSS("127.0.0.1", 0, sessionConfig{
		host:   "127.0.0.1",
		port:   addrPort(t, ssSrvListener.Addr()),
		cipher: ss.TestCipher,
		secret: testSecret,
	})
	if err != nil {
		t.Fatalf("Running client failed: %v", err)
	}
	defer ssCli.Stop()

	socksCon := dialSocks(t, addrPort(t, ssCli.ListenAddr()), addrPort(t, echoListener.Addr()))
	payload := ss.MakeTestPayload(1024)
	_, err = socksCon.Write(payload)
	if err != nil {
		t.Fatalf("Writing to SOCKS connection failed: %v", err)
	}

	buf := make([]byte, 2048)
	n, err := socksCon.Read(buf)
	if err != nil {
		t.Fatalf("Reading from SOCKS connection failed: %v", err)
	}

	// Check received payload matches sent payload
	if bytes.Compare(buf[:n], payload) != 0 {
		t.Fatalf("Wrong data recevied, expected=%v got=%v", payload, buf)
	}

	// Check that target connection closes after closing SOCKS connection
	select {
	case <-echoCloseCh:
		t.Fatalf("SSServer<->EchoServer connection closed before SOCKS connection closed")
	default:
	}
	socksCon.Close()
	select {
	case <-time.After(50 * time.Millisecond):
		t.Fatalf("SSServer<->EchoServer connection not closed after SOCKS connection closed")
	case <-echoCloseCh:
	}
}

func startSSServer(t *testing.T) (net.Listener, service.TCPService) {
	cipher, err := ss.NewCipher(ss.TestCipher, testSecret)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	entry := service.MakeCipherEntry("tst-cipher", cipher, testSecret)
	cipherList := *&list.List{}
	cipherList.PushBack(&entry)
	ciphers := service.NewCipherList()
	ciphers.Update(&cipherList)

	rc := service.NewReplayCache(2)
	tcpsvc := service.NewTCPService(
		ciphers,
		&rc,
		metrics.NewPrometheusShadowsocksMetrics(nil, prometheus.DefaultRegisterer),
		59*time.Second,
	)
	tcpsvc.SetTargetIPValidator(func(i net.IP) *onet.ConnectionError {
		return nil
	})

	l, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatalf("Failed to start TCP listen: %v", err)
	}

	go tcpsvc.Serve(l)
	return l, tcpsvc
}

func startEchoServer(t *testing.T) (net.Listener, chan struct{}) {
	l, err := net.ListenTCP("tcp", nil)
	if err != nil {
		t.Fatalf("Failed to start TCP listen: %v", err)
	}
	closeCh := make(chan struct{})
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Logf("Accepting connection failed: %v\n", err)
			return
		}
		_, err = io.Copy(c, c)
		if err != nil {
			t.Logf(err.Error())
		}
		close(closeCh)
	}()
	return l, closeCh
}

func dialSocks(t *testing.T, socksPort int, targetPort int) (_ net.Conn) {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
	if err != nil {
		t.Fatalf("Connecting to SOCKS server failed: %v", err)
	}

	conn.Write([]byte{
		byte(5), // version
		1,       // number of methods
		byte(0), // method - no auth
	})

	b := make([]byte, 128)
	n, err := conn.Read(b)
	if err != nil {
		t.Fatalf("SOCKS negotiation failed: %v", err)
	} else if n != 2 {
		t.Fatalf("SOCKS initial server reply invalid, expected 2 bytes got=%d", n)
	} else if b[0] != 5 {
		t.Fatalf("SOCKS 5 not supported")
	} else if b[1] != 0 {
		t.Fatalf("SOCKS method negotiation failed, expected=0 got=%d", b[1])
	}

	conn.Write([]byte{
		byte(5),      // version
		1,            // connect command
		0,            // reserved
		1,            // address type - ip
		127, 0, 0, 1, // ip
		byte(targetPort >> 8),
		byte(targetPort),
	})

	n, err = conn.Read(b)
	if err != nil {
		t.Fatalf("SOCKS request failed: %v", err)
	} else if n != 10 {
		t.Fatalf("SOCKS server invalid response, expected 10 bytes got=%d", n)
	} else if b[1] != 0 {
		t.Fatalf("SOCKS server failed")
	}
	return conn
}

func addrPort(t *testing.T, a net.Addr) int {
	_, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatalf(err.Error())
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf(err.Error())
	}
	return port
}
