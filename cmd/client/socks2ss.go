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
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Jigsaw-Code/outline-ss-server/client"
	onet "github.com/Jigsaw-Code/outline-ss-server/net"
	"github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"golang.org/x/crypto/ssh/terminal"
)

var logger *logging.Logger

func init() {
	var prefix = "%{level:.1s}%{time:2006-01-02T15:04:05.000Z07:00} %{pid} %{shortfile}]"
	if terminal.IsTerminal(int(os.Stderr.Fd())) {
		// Add color only if the output is the terminal
		prefix = strings.Join([]string{"%{color}", prefix, "%{color:reset}"}, "")
	}
	logging.SetFormatter(logging.MustStringFormatter(strings.Join([]string{prefix, " %{message}"}, "")))
	logging.SetBackend(logging.NewLogBackend(os.Stderr, "", 0))
	logger = logging.MustGetLogger("")
}

type sessionConfig struct {
	host   string
	port   int
	cipher string
	secret string
}

func parseAccessKey(k string) (sessionConfig, error) {
	u, err := url.Parse(k)
	if err != nil {
		return sessionConfig{}, err
	}

	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return sessionConfig{}, fmt.Errorf("invalid port: %v", err)
	}

	cipherAndSecret := u.User.String()

	// If we see a ":" in the string, assume its not base64 encoded and skip decoding
	if !strings.Contains(cipherAndSecret, ":") {
		// Attempt to decode with padding
		b, err := base64.StdEncoding.DecodeString(cipherAndSecret)
		if err != nil {
			// Attempt to decode without padding
			b, err = base64.RawStdEncoding.DecodeString(cipherAndSecret)
			if err != nil {
				return sessionConfig{}, fmt.Errorf("invalid password in key: %v", err)
			}
		}
		cipherAndSecret = string(b)
	}

	p := strings.Split(cipherAndSecret, ":")
	if len(p) != 2 {
		return sessionConfig{}, fmt.Errorf("invalid password in key")
	}

	return sessionConfig{
		host:   u.Hostname(),
		port:   port,
		cipher: p[0],
		secret: p[1],
	}, nil
}

type SocksToSS struct {
	config   sessionConfig
	listener *net.TCPListener
}

// RunSocksToSS starts a SOCKS server which proxies connections to the specified shadowsocks server.
func RunSocksToSS(bindAddr string, listenPort int, config sessionConfig) (*SocksToSS, error) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(bindAddr), Port: listenPort})
	if err != nil {
		return nil, fmt.Errorf("listenTCP failed: %v", err)
	}
	logger.Infof("Listenting at %v", listener.Addr())

	ssClient, err := client.NewClient(config.host, config.port, config.secret, config.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed connecting to server: %v", err)
	}

	go func() {
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					logger.Info("SOCKS listener closed")
				} else {
					logger.Errorf("Accepting SOCKS connection failed: %v\n", err)
				}
				break
			}
			go func() {
				defer clientConn.Close()

				tgtAddr, err := socks.Handshake(clientConn)
				if err != nil {
					logger.Errorf("SOCKS handshake failed: %v", err)
					return
				}

				logger.Debugf("Opening connection for %s", tgtAddr)
				targetConn, err := ssClient.DialTCP(nil, tgtAddr.String())
				if err != nil {
					logger.Errorf("Failed to dial: %v", err)
					return
				}
				defer targetConn.Close()
				_, _, err = onet.Relay(clientConn, targetConn)
				if err != nil {
					logger.Errorf("Relay failed: %v", err)
					return
				}
				logger.Debugf("Connection closed %s", tgtAddr)
			}()
		}
	}()
	return &SocksToSS{listener: listener}, nil
}

// ListenAddr returns the listening address used by the SOCKS server
func (s *SocksToSS) ListenAddr() net.Addr {
	return s.listener.Addr()
}

// Stop stops the SOCKS server
func (s *SocksToSS) Stop() error {
	return s.listener.Close()
}

func main() {
	var flags struct {
		BindAddr   string
		ListenPort int
		AccessKey  string
		Verbose    bool
	}

	flag.StringVar(&flags.BindAddr, "bind", "127.0.0.1", "Local address to bind to.")
	flag.IntVar(&flags.ListenPort, "port", 1080, "Local port to listen on.")
	flag.StringVar(&flags.AccessKey, "key", "", "Access key specifying how to connect to the server. Only ss:// links are accepted.")
	flag.BoolVar(&flags.Verbose, "verbose", false, "Enables verbose logging output")

	flag.Parse()

	if flags.Verbose {
		logging.SetLevel(logging.DEBUG, "")
	} else {
		logging.SetLevel(logging.INFO, "")
	}

	if flags.AccessKey == "" {
		flag.Usage()
		return
	}

	sc, err := parseAccessKey(flags.AccessKey)
	if err != nil {
		logger.Fatalf("Invalid key: %v", err)
	}

	// TODO: add UDP support for ScoksToSS
	_, err = RunSocksToSS(flags.BindAddr, flags.ListenPort, sc)
	if err != nil {
		logger.Fatalf("Failed running client: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}
