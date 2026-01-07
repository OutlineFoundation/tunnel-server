// Copyright 2018 The Outline Authors
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

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/require"

	"golang.getoutline.org/tunnel-server/service/metrics"
)

func init() {
	logging.SetLevel(logging.INFO, "")
}

func allowAll(ip net.IP) error {
	// Allow access to localhost so that we can run integration tests with
	// an actual destination server.
	return nil
}

func makeLocalhostListener(t testing.TB) *net.TCPListener {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err, "ListenTCP failed: %v", err)
	return listener
}

func startDiscardServer(t testing.TB) (*net.TCPListener, *sync.WaitGroup) {
	listener := makeLocalhostListener(t)
	var running sync.WaitGroup
	running.Add(1)
	go func() {
		defer running.Done()
		for {
			clientConn, err := listener.AcceptTCP()
			if err != nil {
				t.Logf("AcceptTCP failed: %v", err)
				return
			}
			running.Add(1)
			go func() {
				defer running.Done()
				io.Copy(io.Discard, clientConn)
				clientConn.Close()
			}()
		}
	}()
	return listener, &running
}

// Simulates receiving invalid TCP connection attempts on a server with 100 ciphers.
func BenchmarkTCPFindCipherFail(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		b.Fatalf("ListenTCP failed: %v", err)
	}

	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	for n := 0; n < b.N; n++ {
		go func() {
			conn, err := net.Dial("tcp", listener.Addr().String())
			require.NoErrorf(b, err, "Failed to dial %v: %v", listener.Addr(), err)
			conn.Write(testPayload)
			conn.Close()
		}()
		clientConn, err := listener.AcceptTCP()
		if err != nil {
			b.Fatalf("AcceptTCP failed: %v", err)
		}
		clientIP := clientConn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr()
		b.StartTimer()
		findAccessKey(clientConn, clientIP, cipherList, noopLogger())
		b.StopTimer()
	}
}

func TestCompatibleCiphers(t *testing.T) {
	for _, cipherName := range [](string){shadowsocks.CHACHA20IETFPOLY1305, shadowsocks.AES256GCM, shadowsocks.AES192GCM, shadowsocks.AES128GCM} {
		cryptoKey, _ := shadowsocks.NewEncryptionKey(cipherName, "dummy secret")
		// We need at least this many bytes to assess whether a TCP stream corresponds
		// to this cipher.
		requires := cryptoKey.SaltSize() + 2 + cryptoKey.TagSize()
		if requires > bytesForKeyFinding {
			t.Errorf("Cipher %v required %v bytes > bytesForKeyFinding (%v)", cipherName, requires, bytesForKeyFinding)
		}
		// Any TCP stream for this cipher will deliver at least this many bytes before
		// requiring the proxy to act.
		provides := requires + cryptoKey.TagSize()
		if provides < bytesForKeyFinding {
			t.Errorf("Cipher %v provides %v bytes < bytesForKeyFinding (%v)", cipherName, provides, bytesForKeyFinding)
		}
	}
}

// Fake StreamConn
// 1-way pipe, representing the upstream flow as seen by the server.
type conn struct {
	transport.StreamConn
	clientAddr net.Addr
	reader     io.ReadCloser
	writer     io.WriteCloser
}

func (c *conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	// Any downstream data is ignored.
	return len(b), nil
}

func (c *conn) Close() error {
	e1 := c.reader.Close()
	e2 := c.writer.Close()
	if e1 != nil {
		return e1
	}
	return e2
}

func (c *conn) LocalAddr() net.Addr {
	return nil
}

func (c *conn) RemoteAddr() net.Addr {
	return c.clientAddr
}

func (c *conn) SetDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return errors.New("SetDeadline is not supported")
}

func (c *conn) CloseRead() error {
	return c.reader.Close()
}

func (c *conn) CloseWrite() error {
	return nil
}

// Simulates receiving valid TCP connection attempts from 100 different users,
// each with their own cipher and their own IP address.
func BenchmarkTCPFindCipherRepeat(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(makeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	cipherEntries := [numCiphers]*CipherEntry{}
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	for cipherNumber, element := range snapshot {
		cipherEntries[cipherNumber] = element.Value.(*CipherEntry)
	}
	for n := 0; n < b.N; n++ {
		cipherNumber := byte(n % numCiphers)
		reader, writer := io.Pipe()
		clientIP := netip.AddrFrom4([4]byte{192, 0, 2, cipherNumber})
		addr := netip.AddrPortFrom(clientIP, 54321)
		c := conn{clientAddr: net.TCPAddrFromAddrPort(addr), reader: reader, writer: writer}
		cipher := cipherEntries[cipherNumber].CryptoKey
		go shadowsocks.NewWriter(writer, cipher).Write(makeTestPayload(50))
		b.StartTimer()
		_, _, _, _, err := findAccessKey(&c, clientIP, cipherList, noopLogger())
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		c.Close()
	}
}

// Stub implementation for shadowsocks authentication metrics.
type fakeShadowsocksMetrics struct{}

var _ ShadowsocksConnMetrics = (*fakeShadowsocksMetrics)(nil)

func (m *fakeShadowsocksMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
}

// Stub metrics implementation for testing replay defense.
type probeTestMetrics struct {
	mu          sync.Mutex
	probeData   []int64
	probeStatus []string
	closeStatus []string
}

var _ TCPConnMetrics = (*probeTestMetrics)(nil)

var _ ShadowsocksConnMetrics = (*fakeShadowsocksMetrics)(nil)

func (m *probeTestMetrics) AddClose(status string, data metrics.ProxyMetrics, duration time.Duration) {
	m.mu.Lock()
	m.closeStatus = append(m.closeStatus, status)
	m.mu.Unlock()
}

func (m *probeTestMetrics) AddAuthentication(accessKey string) {
}

func (m *probeTestMetrics) AddProbe(status, drainResult string, clientProxyBytes int64) {
	m.mu.Lock()
	m.probeData = append(m.probeData, clientProxyBytes)
	m.probeStatus = append(m.probeStatus, status)
	m.mu.Unlock()
}

func (m *probeTestMetrics) AddCipherSearch(accessKeyFound bool, timeToCipher time.Duration) {
}

func (m *probeTestMetrics) countStatuses() map[string]int {
	counts := make(map[string]int)
	for _, status := range m.closeStatus {
		counts[status] = counts[status] + 1
	}
	return counts
}

func probe(serverAddr *net.TCPAddr, bytesToSend []byte) error {
	conn, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("DialTCP failed: %w", err)
	}

	n, err := conn.Write(bytesToSend)
	if err != nil || n != len(bytesToSend) {
		return fmt.Errorf("Write failed. bytes written: %v, err: %w", n, err)
	}
	conn.CloseWrite()

	nRead, err := conn.Read(make([]byte, 1))
	if err != io.EOF || nRead != 0 {
		return fmt.Errorf("Read not EOF. bytes read: %v, err: %w", nRead, err)
	}
	return nil
}

func TestProbeRandom(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, 200*time.Millisecond)
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	// 221 is the largest random probe reported by https://gfw.report/blog/gfw_shadowsocks/
	buf := make([]byte, 221)
	for numBytesToSend := 0; numBytesToSend < len(buf); numBytesToSend++ {
		bytesToSend := buf[:numBytesToSend]
		rand.Read(bytesToSend)
		err := probe(listener.Addr().(*net.TCPAddr), bytesToSend)
		require.NoError(t, err, "Failed on byte %v: %v", numBytesToSend, err)
	}
	require.Nil(t, listener.Close())
	<-done
	require.Equal(t, len(buf), len(testMetrics.probeData))
}

func makeClientBytesBasic(t *testing.T, cryptoKey *shadowsocks.EncryptionKey, targetAddr string) []byte {
	var buffer bytes.Buffer
	socksTargetAddr := socks.ParseAddr(targetAddr)
	// Assumes IPv4, as that's the common case.
	require.Equal(t, 1+4+2, len(socksTargetAddr))
	ssw := shadowsocks.NewWriter(&buffer, cryptoKey)
	n, err := ssw.Write(socksTargetAddr)
	require.NoError(t, err, "Write failed: %v", err)
	require.Equal(t, len(socksTargetAddr), n, "Write failed: %v", err)
	require.Equal(t, 32+2+16+7+16, buffer.Len()) // 73

	payload := make([]byte, 100)
	rand.Read(payload)
	n, err = ssw.Write(payload[:60])
	require.NoError(t, err, "Write failed: %v", err)
	require.Equal(t, 60, n)
	require.Equal(t, 73+2+16+60+16, buffer.Len()) // 167

	n, err = ssw.Write(payload[60:])
	require.NoError(t, err, "Write failed: %v", err)
	require.Equal(t, 40, n)
	require.Equal(t, 167+2+16+40+16, buffer.Len()) // 241

	return buffer.Bytes()
}

func makeClientBytesCoalesced(t *testing.T, cryptoKey *shadowsocks.EncryptionKey, targetAddr string) []byte {
	var buffer bytes.Buffer
	socksTargetAddr := socks.ParseAddr(targetAddr)
	ssw := shadowsocks.NewWriter(&buffer, cryptoKey)
	n, err := ssw.LazyWrite(socksTargetAddr)
	require.NoError(t, err, "LazyWrite failed: %v", err)
	require.Equal(t, len(socksTargetAddr), n, "LazyWrite failed: %v", err)
	n, err = ssw.Write([]byte("initial data"))
	require.NoError(t, err, "Write failed: %v", err)
	require.Equal(t, 12, n)
	require.Equal(t, 32+2+16+7+12+16, buffer.Len()) // 85

	n, err = ssw.Write([]byte("more data"))
	require.NoError(t, err, "Write failed: %v", err)
	require.Equal(t, 9, n)
	return buffer.Bytes()
}

func firstCipher(cipherList CipherList) *shadowsocks.EncryptionKey {
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cipherEntry := snapshot[0].Value.(*CipherEntry)
	return cipherEntry.CryptoKey
}

func TestProbeClientBytesBasicTruncated(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	cipher := firstCipher(cipherList)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, 200*time.Millisecond)
	handler.SetTargetDialer(MakeValidatingTCPStreamDialer(allowAll, 0))
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	discardListener, discardWait := startDiscardServer(t)
	initialBytes := makeClientBytesBasic(t, cipher, discardListener.Addr().String())
	for numBytesToSend := 0; numBytesToSend < len(initialBytes); numBytesToSend++ {
		bytesToSend := initialBytes[:numBytesToSend]
		err := probe(listener.Addr().(*net.TCPAddr), bytesToSend)
		require.NoError(t, err, "Failed for %v bytes sent: %v", numBytesToSend, err)
	}
	listener.Close()
	<-done
	statusCount := testMetrics.countStatuses()
	require.Equal(t, 50, statusCount["ERR_CIPHER"])
	require.Equal(t, 7+16, statusCount["ERR_READ_ADDRESS"])
	require.Equal(t, 2, statusCount["OK"]) // On the chunk boundaries.
	require.Equal(t, len(initialBytes)-50-7-16-2, statusCount["ERR_RELAY_CLIENT"])
	// We only count as probes failures in the first 50 bytes.
	require.Equal(t, 50, len(testMetrics.probeData))
	discardListener.Close()
	discardWait.Wait()
}

func TestProbeClientBytesBasicModified(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	cipher := firstCipher(cipherList)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, 200*time.Millisecond)
	handler.SetTargetDialer(MakeValidatingTCPStreamDialer(allowAll, 0))
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	discardListener, discardWait := startDiscardServer(t)
	initialBytes := makeClientBytesBasic(t, cipher, discardListener.Addr().String())
	bytesToSend := make([]byte, len(initialBytes))
	for byteToModify := 0; byteToModify < len(initialBytes); byteToModify++ {
		copy(bytesToSend, initialBytes)
		bytesToSend[byteToModify] = 255 - bytesToSend[byteToModify]
		err := probe(listener.Addr().(*net.TCPAddr), bytesToSend)
		require.NoError(t, err, "Failed modified byte %v: %v", byteToModify, err)
	}

	listener.Close()
	<-done
	statusCount := testMetrics.countStatuses()
	require.Equal(t, 50, statusCount["ERR_CIPHER"])
	require.Equal(t, 7+16, statusCount["ERR_READ_ADDRESS"])
	require.Equal(t, len(initialBytes)-50-7-16, statusCount["ERR_RELAY_CLIENT"])
	require.Equal(t, 50, len(testMetrics.probeData))
	discardListener.Close()
	discardWait.Wait()
}

func TestProbeClientBytesCoalescedModified(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	cipher := firstCipher(cipherList)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, 200*time.Millisecond)
	handler.SetTargetDialer(MakeValidatingTCPStreamDialer(allowAll, 0))
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	discardListener, discardWait := startDiscardServer(t)
	initialBytes := makeClientBytesCoalesced(t, cipher, discardListener.Addr().String())
	bytesToSend := make([]byte, len(initialBytes))
	for byteToModify := 0; byteToModify < len(initialBytes); byteToModify++ {
		copy(bytesToSend, initialBytes)
		bytesToSend[byteToModify] = 255 - bytesToSend[byteToModify]
		err := probe(listener.Addr().(*net.TCPAddr), bytesToSend)
		require.NoError(t, err, "Failed modified byte %v: %v", byteToModify, err)
	}
	listener.Close()
	<-done
	statusCount := testMetrics.countStatuses()
	require.Equal(t, 50, statusCount["ERR_CIPHER"])
	require.Equal(t, len(initialBytes)-50, statusCount["ERR_READ_ADDRESS"]+statusCount["ERR_RELAY_CLIENT"])
	discardListener.Close()
	discardWait.Wait()
}

func makeServerBytes(t *testing.T, cryptoKey *shadowsocks.EncryptionKey) []byte {
	var buffer bytes.Buffer
	ssw := shadowsocks.NewWriter(&buffer, cryptoKey)
	_, err := ssw.Write([]byte("initial data"))
	require.NoError(t, err, "Write failed: %v", err)
	_, err = ssw.Write([]byte("more data"))
	require.NoError(t, err, "Write failed: %v", err)
	return buffer.Bytes()
}

func TestProbeServerBytesModified(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	cipher := firstCipher(cipherList)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, 200*time.Millisecond)
	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	initialBytes := makeServerBytes(t, cipher)
	bytesToSend := make([]byte, len(initialBytes))
	for byteToModify := 0; byteToModify < len(initialBytes); byteToModify++ {
		copy(bytesToSend, initialBytes)
		bytesToSend[byteToModify] = 255 - bytesToSend[byteToModify]
		err := probe(listener.Addr().(*net.TCPAddr), bytesToSend)
		require.NoError(t, err, "Failed modified byte %v: %v", byteToModify, err)
	}
	listener.Close()
	<-done
	statusCount := testMetrics.countStatuses()
	require.Equal(t, 50, statusCount["ERR_CIPHER"])
	require.Equal(t, len(initialBytes)-50, statusCount["ERR_READ_ADDRESS"])
	require.Equal(t, 50, len(testMetrics.probeData))
}

func TestReplayDefense(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	replayCache := NewReplayCache(5)
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, &replayCache, testMetrics, nil)
	handler := NewStreamHandler(authFunc, testTimeout)
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cipherEntry := snapshot[0].Value.(*CipherEntry)
	cipher := cipherEntry.CryptoKey
	reader, writer := io.Pipe()
	go shadowsocks.NewWriter(writer, cipher).Write([]byte{0})
	preamble := make([]byte, cipher.SaltSize()+2+cipher.TagSize())
	if _, err := io.ReadFull(reader, preamble); err != nil {
		t.Fatal(err)
	}

	run := func() *net.TCPConn {
		conn, err := net.DialTCP(listener.Addr().Network(), nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		n, err := conn.Write(preamble)
		if n < len(preamble) {
			t.Error(err)
		}
		return conn
	}

	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	// First run.
	conn1 := run()
	// Wait for the close.  This ensures that conn1 and conn2 can't be
	// processed out of order at the proxy.
	conn1.CloseWrite()
	conn1.Read(make([]byte, 1))
	if len(testMetrics.probeData) != 0 {
		t.Errorf("First connection should not have triggered probe detection: %v", testMetrics.probeData[0])
	}

	// Replay.
	conn2 := run()
	// Wait for the connection to be closed by the proxy after testTimeout.
	conn2.CloseWrite()
	conn2.Read(make([]byte, 1))

	conn1.Close()
	listener.Close()
	<-done

	if len(testMetrics.probeData) == 1 {
		clientProxyData := testMetrics.probeData[0]
		if clientProxyData != int64(len(preamble)) {
			t.Errorf("Unexpected probe data: %v", clientProxyData)
		}
		status := testMetrics.probeStatus[0]
		if status != "ERR_REPLAY_CLIENT" {
			t.Errorf("Unexpected TCP probe status: %s", status)
		}
	} else {
		t.Error("Replay should have triggered probe detection")
	}
	if len(testMetrics.closeStatus) == 2 {
		status := testMetrics.closeStatus[1]
		if status != "ERR_REPLAY_CLIENT" {
			t.Errorf("Unexpected TCP close status: %s", status)
		}
	} else {
		t.Error("Replay should have reported an error status")
	}
}

func TestReverseReplayDefense(t *testing.T) {
	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	replayCache := NewReplayCache(5)
	testMetrics := &probeTestMetrics{}
	const testTimeout = 200 * time.Millisecond
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, &replayCache, testMetrics, nil)
	handler := NewStreamHandler(authFunc, testTimeout)
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cipherEntry := snapshot[0].Value.(*CipherEntry)
	cipher := cipherEntry.CryptoKey
	reader, writer := io.Pipe()
	ssWriter := shadowsocks.NewWriter(writer, cipher)
	// Use a server-marked salt in the client's preamble.
	ssWriter.SetSaltGenerator(cipherEntry.SaltGenerator)
	go ssWriter.Write([]byte{0})
	preamble := make([]byte, 32+2+16)
	if _, err := io.ReadFull(reader, preamble); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	conn, err := net.Dial(listener.Addr().Network(), listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, err := conn.Write(preamble)
	if n < len(preamble) {
		t.Error(err)
	}
	conn.Close()
	listener.Close()
	<-done

	// The preamble should have been marked as a server replay.
	if len(testMetrics.probeData) == 1 {
		clientProxyData := testMetrics.probeData[0]
		if clientProxyData != int64(len(preamble)) {
			t.Errorf("Unexpected probe data: %v", clientProxyData)
		}
		status := testMetrics.probeStatus[0]
		if status != "ERR_REPLAY_SERVER" {
			t.Errorf("Unexpected TCP probe status: %s", status)
		}
	} else {
		t.Error("Replay should have triggered probe detection")
	}
	if len(testMetrics.closeStatus) == 1 {
		status := testMetrics.closeStatus[0]
		if status != "ERR_REPLAY_SERVER" {
			t.Errorf("Unexpected TCP close status: %s", status)
		}
	} else {
		t.Error("Replay should have reported an error status")
	}
}

// Test 49, 50, and 51 bytes to ensure they have the same behavior.
// 50 bytes used to be the cutoff for different behavior.
func TestTCPProbeTimeout(t *testing.T) {
	probeExpectTimeout(t, 49)
	probeExpectTimeout(t, 50)
	probeExpectTimeout(t, 51)
}

func probeExpectTimeout(t *testing.T, payloadSize int) {
	const testTimeout = 200 * time.Millisecond

	listener := makeLocalhostListener(t)
	cipherList, err := MakeTestCiphers(makeTestSecrets(5))
	require.NoError(t, err, "MakeTestCiphers failed: %v", err)
	testMetrics := &probeTestMetrics{}
	authFunc := NewShadowsocksStreamAuthenticator(cipherList, nil, &fakeShadowsocksMetrics{}, nil)
	handler := NewStreamHandler(authFunc, testTimeout)

	done := make(chan struct{})
	go func() {
		StreamServe(
			WrapStreamAcceptFunc(listener.AcceptTCP),
			func(ctx context.Context, conn transport.StreamConn) { handler.HandleStream(ctx, conn, testMetrics) },
		)
		done <- struct{}{}
	}()

	testPayload := makeTestPayload(payloadSize)
	timerStart := time.Now()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial %v: %v", listener.Addr(), err)
	}
	conn.Write(testPayload)
	buf := make([]byte, 1024)
	bytesRead, err := conn.Read(buf) // will hang until connection is closed
	elapsedTime := time.Since(timerStart)
	switch {
	case err != io.EOF:
		t.Fatalf("Expected error EOF, got %v", err)
	case bytesRead > 0:
		t.Fatalf("Expected to read 0 bytes, got %v bytes", bytesRead)
	case elapsedTime < testTimeout || elapsedTime > testTimeout+10*time.Millisecond:
		t.Fatalf("Expected elapsed time close to %v, got %v", testTimeout, elapsedTime)
	default:
		// ok
	}

	listener.Close()
	<-done

	if len(testMetrics.probeData) == 1 {
		clientProxyData := testMetrics.probeData[0]
		if clientProxyData != int64(payloadSize) {
			t.Errorf("Unexpected probe data: %v, expected %d", clientProxyData, payloadSize)
		}
	} else {
		t.Error("Bad handshake should have triggered probe detection")
	}
	if len(testMetrics.probeStatus) == 1 {
		status := testMetrics.probeStatus[0]
		if status != "ERR_CIPHER" {
			t.Errorf("Unexpected TCP probe status: %s", status)
		}
	} else {
		t.Error("Bad handshake should have reported an error status")
	}
	if len(testMetrics.closeStatus) == 1 {
		status := testMetrics.closeStatus[0]
		if status != "ERR_CIPHER" {
			t.Errorf("Unexpected TCP close status: %s", status)
		}
	} else {
		t.Error("Bad handshake should have reported an error status")
	}
}

func TestStreamServeEarlyClose(t *testing.T) {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	err = tcpListener.Close()
	require.NoError(t, err)
	// This should return quickly, without timing out or calling the handler.
	StreamServe(WrapStreamAcceptFunc(tcpListener.AcceptTCP), nil)
}

// Makes sure the TCP listener returns [io.ErrClosed] on Close().
func TestClosedTCPListenerError(t *testing.T) {
	tcpListener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	accept := WrapStreamAcceptFunc(tcpListener.AcceptTCP)
	err = tcpListener.Close()
	require.NoError(t, err)
	_, err = accept()
	require.ErrorIs(t, err, net.ErrClosed)
}
