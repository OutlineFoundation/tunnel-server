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
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	logging "github.com/op/go-logging"
	"github.com/shadowsocks/go-shadowsocks2/socks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	onet "golang.getoutline.org/tunnel-server/net"
)

const timeout = 5 * time.Minute

var clientAddr = net.UDPAddr{IP: []byte{192, 0, 2, 1}, Port: 12345}

var targetAddr = net.UDPAddr{IP: []byte{192, 0, 2, 2}, Port: 54321}
var localAddr = net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 9}
var dnsAddr = net.UDPAddr{IP: []byte{192, 0, 2, 3}, Port: 53}

var natCryptoKey *shadowsocks.EncryptionKey

func init() {
	logging.SetLevel(logging.INFO, "")
	natCryptoKey, _ = shadowsocks.NewEncryptionKey(shadowsocks.CHACHA20IETFPOLY1305, "test password")
}

type fakePacket struct {
	addr    net.Addr
	payload []byte
	err     error
}

type packetListener struct {
	conn net.PacketConn
}

func (ln *packetListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	return ln.conn, nil
}

func WrapWithValidatingPacketListener(conn net.PacketConn, targetIPValidator onet.TargetIPValidator) transport.PacketListener {
	return &packetListener{
		&validatingPacketConn{
			PacketConn:        conn,
			targetIPValidator: targetIPValidator,
		},
	}
}

type fakePacketConn struct {
	net.PacketConn
	send     chan fakePacket
	recv     chan fakePacket
	deadline time.Time
	mu       sync.Mutex
}

func makePacketConn() *fakePacketConn {
	return &fakePacketConn{
		send: make(chan fakePacket, 1),
		recv: make(chan fakePacket),
	}
}

func (conn *fakePacketConn) getReadDeadline() time.Time {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.deadline
}

func (conn *fakePacketConn) SetReadDeadline(deadline time.Time) error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	conn.deadline = deadline
	return nil
}

func (conn *fakePacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	var err error
	defer func() {
		if recover() != nil {
			err = net.ErrClosed
		}
	}()

	conn.send <- fakePacket{addr, payload, nil}
	return len(payload), err
}

func (conn *fakePacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	pkt, ok := <-conn.recv
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(buffer, pkt.payload)
	if n < len(pkt.payload) {
		return n, pkt.addr, io.ErrShortBuffer
	}
	return n, pkt.addr, pkt.err
}

func (conn *fakePacketConn) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	close(conn.send)
	close(conn.recv)
	return nil
}

func (conn *fakePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 9999}
}

func (conn *fakePacketConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 8888}
}

type udpReport struct {
	accessKey, status                  string
	clientProxyBytes, proxyTargetBytes int64
}

// Stub metrics implementation for testing NAT behaviors.
type natTestMetrics struct {
	natEntriesAdded int
}

var _ NATMetrics = (*natTestMetrics)(nil)

func (m *natTestMetrics) AddNATEntry() {
	m.natEntriesAdded++
}
func (m *natTestMetrics) RemoveNATEntry() {}

type fakeUDPAssociationMetrics struct {
	accessKey       string
	upstreamPackets []udpReport
	mu              sync.Mutex
}

var _ UDPAssociationMetrics = (*fakeUDPAssociationMetrics)(nil)

func (m *fakeUDPAssociationMetrics) AddAuthentication(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accessKey = key
}

func (m *fakeUDPAssociationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upstreamPackets = append(m.upstreamPackets, udpReport{m.accessKey, status, clientProxyBytes, proxyTargetBytes})
}

func (m *fakeUDPAssociationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}

func (m *fakeUDPAssociationMetrics) AddClose() {}

// sendSSPayload sends a single Shadowsocks packet to the provided connection.
// The packet is constructed with the given address, cipher, and payload.
func sendSSPayload(conn *fakePacketConn, addr net.Addr, cipher *shadowsocks.EncryptionKey, payload []byte) {
	socksAddr := socks.ParseAddr(addr.String())
	plaintext := append(socksAddr, payload...)
	ciphertext := make([]byte, cipher.SaltSize()+len(plaintext)+cipher.TagSize())
	shadowsocks.Pack(ciphertext, plaintext, cipher)
	conn.recv <- fakePacket{
		addr:    &clientAddr,
		payload: ciphertext,
	}
}

// startTestHandler creates a new association handler with a fake
// client and target connection for testing purposes. It also starts a
// PacketServe goroutine to handle incoming packets on the client connection.
func startTestHandler() (AssociationHandler, func(target net.Addr, payload []byte), *fakePacketConn) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetPacketListener(&packetListener{targetConn})
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
	}, &natTestMetrics{})
	return handler, func(target net.Addr, payload []byte) {
		sendSSPayload(clientConn, target, cipher, payload)
	}, targetConn
}

func TestAssociationCloseWhileReading(t *testing.T) {
	assoc := &association{
		pc:         makePacketConn(),
		clientAddr: &clientAddr,
		readCh:     make(chan *packet),
	}
	go func() {
		buf := make([]byte, 1024)
		assoc.Read(buf)
	}()

	err := assoc.Close()

	assert.NoError(t, err, "Close should not panic or return an error")
}

func TestAssociationHandler_Handle_IPFilter(t *testing.T) {
	t.Run("RequirePublicIP blocks localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetPacketListener(WrapWithValidatingPacketListener(targetConn, onet.RequirePublicIP))

		sendPayload(&localAddr, []byte{1, 2, 3})

		select {
		case <-targetConn.send:
			t.Errorf("Expected no packets to be sent")
		case <-time.After(100 * time.Millisecond):
			return
		}
	})

	t.Run("allowAll allows localhost", func(t *testing.T) {
		handler, sendPayload, targetConn := startTestHandler()
		handler.SetTargetPacketListener(WrapWithValidatingPacketListener(targetConn, allowAll))

		sendPayload(&localAddr, []byte{1, 2, 3})

		sent := <-targetConn.send
		if !bytes.Equal([]byte{1, 2, 3}, sent.payload) {
			t.Errorf("Expected %v, but got %v", []byte{1, 2, 3}, sent.payload)
		}
	})
}

func TestUpstreamMetrics(t *testing.T) {
	ciphers, _ := MakeTestCiphers([]string{"asdf"})
	cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
	handler := NewAssociationHandler(ciphers, nil)
	clientConn := makePacketConn()
	targetConn := makePacketConn()
	handler.SetTargetPacketListener(&packetListener{targetConn})
	metrics := &fakeUDPAssociationMetrics{}
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, metrics)
	}, &natTestMetrics{})

	// Test both the first-packet and subsequent-packet cases.
	const N = 10
	for i := 1; i <= N; i++ {
		sendSSPayload(clientConn, &targetAddr, cipher, make([]byte, i))
		<-targetConn.send
	}

	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	assert.Equal(t, N, len(metrics.upstreamPackets), "Expected %d reports, not %d", N, len(metrics.upstreamPackets))
	for i, report := range metrics.upstreamPackets {
		assert.Equal(t, int64(i+1), report.proxyTargetBytes, "Expected %d payload bytes, not %d", i+1, report.proxyTargetBytes)
		assert.Greater(t, report.clientProxyBytes, report.proxyTargetBytes, "Expected nonzero input overhead (%d > %d)", report.clientProxyBytes, report.proxyTargetBytes)
		assert.Equal(t, "id-0", report.accessKey, "Unexpected access key name: %s", report.accessKey)
		assert.Equal(t, "OK", report.status, "Wrong status: %s", report.status)
	}
}

func assertAlmostEqual(t *testing.T, a, b time.Time) {
	delta := a.Sub(b)
	limit := 100 * time.Millisecond
	if delta > limit || -delta > limit {
		t.Errorf("Times are not close: %v, %v", a, b)
	}
}

func assertUDPAddrEqual(t *testing.T, a net.Addr, b *net.UDPAddr) {
	addr, ok := a.(*net.UDPAddr)
	if !ok || !addr.IP.Equal(b.IP) || addr.Port != b.Port || addr.Zone != b.Zone {
		t.Errorf("Mismatched address: %v != %v", a, b)
	}
}

// Implements net.Error
type fakeTimeoutError struct {
	error
}

func (e *fakeTimeoutError) Timeout() bool {
	return true
}

func (e *fakeTimeoutError) Temporary() bool {
	return false
}

func TestTimedPacketConn(t *testing.T) {
	t.Run("Write", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler()

		buf := []byte{1}
		sendPayload(&targetAddr, buf)

		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &targetAddr)
	})

	t.Run("WriteDNS", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler()

		// Simulate one DNS query being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
		sent := <-targetConn.send
		if !bytes.Equal(sent.payload, buf) {
			t.Errorf("Mismatched payload: %v != %v", sent.payload, buf)
		}
		assertUDPAddrEqual(t, sent.addr, &dnsAddr)
	})

	t.Run("WriteDNSMultiple", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler()

		// Simulate three DNS queries being sent.
		buf := []byte{1}
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// DNS-only connections have a fixed timeout of 17 seconds.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("WriteMixed", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler()

		// Simulate both non-DNS and DNS packets being sent.
		buf := []byte{1}
		sendPayload(&targetAddr, buf)
		<-targetConn.send
		sendPayload(&dnsAddr, buf)
		<-targetConn.send

		// Mixed DNS and non-DNS connections should have the user-specified timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("FastClose", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(&packetListener{targetConn})
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})

		// Send one DNS query.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close immediately.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now())
	})

	t.Run("NoFastClose_NotDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(&packetListener{targetConn})
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})

		// Send one non-DNS packet.
		sendSSPayload(clientConn, &targetAddr, cipher, []byte{1})
		sent := <-targetConn.send
		require.Len(t, sent.payload, 1)
		// Send the response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &targetAddr, payload: response}
		targetConn.recv <- received
		sent, ok := <-clientConn.send
		if !ok {
			t.Error("clientConn was closed")
		}

		// targetConn should be scheduled to close after the full timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(timeout))
	})

	t.Run("NoFastClose_MultipleDNS", func(t *testing.T) {
		ciphers, _ := MakeTestCiphers([]string{"asdf"})
		cipher := ciphers.SnapshotForClientIP(netip.Addr{})[0].Value.(*CipherEntry).CryptoKey
		handler := NewAssociationHandler(ciphers, nil)
		clientConn := makePacketConn()
		targetConn := makePacketConn()
		handler.SetTargetPacketListener(&packetListener{targetConn})
		go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
			handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
		}, &natTestMetrics{})

		// Send two DNS packets.
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{1})
		<-targetConn.send
		sendSSPayload(clientConn, &dnsAddr, cipher, []byte{2})
		<-targetConn.send

		// Send a response.
		response := []byte{1, 2, 3, 4, 5}
		received := fakePacket{addr: &dnsAddr, payload: response}
		targetConn.recv <- received
		<-clientConn.send

		// targetConn should be scheduled to close after the DNS timeout.
		assertAlmostEqual(t, targetConn.getReadDeadline(), time.Now().Add(17*time.Second))
	})

	t.Run("Timeout", func(t *testing.T) {
		_, sendPayload, targetConn := startTestHandler()

		// Simulate a non-DNS initial packet.
		sendPayload(&targetAddr, []byte{1})
		<-targetConn.send
		// Simulate a read timeout.
		received := fakePacket{err: &fakeTimeoutError{}}
		before := time.Now()
		targetConn.recv <- received
		// Wait for targetConn to close.
		if _, ok := <-targetConn.send; ok {
			t.Error("targetConn should be closed due to read timeout")
		}

		// targetConn should be closed as soon as the timeout error is received.
		assertAlmostEqual(t, before, time.Now())
	})
}

func TestNATMap(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		nm := newNATmap()
		if nm.Get("foo") != nil {
			t.Error("Expected nil value from empty NAT map")
		}
	})

	t.Run("Add", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc1 := &association{}

		nm.Add(addr.String(), assoc1)
		assert.Equal(t, assoc1, nm.Get(addr.String()), "Get should return the correct connection")

		assoc2 := &association{}
		nm.Add(addr.String(), assoc2)
		assert.Equal(t, assoc2, nm.Get(addr.String()), "Adding with the same address should overwrite the entry")
	})

	t.Run("Get", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc := &association{}
		nm.Add(addr.String(), assoc)

		assert.Equal(t, assoc, nm.Get(addr.String()), "Get should return the correct connection for an existing address")

		addr2 := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 5678}
		assert.Nil(t, nm.Get(addr2.String()), "Get should return nil for a non-existent address")
	})

	t.Run("Del", func(t *testing.T) {
		nm := newNATmap()
		addr := &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1234}
		assoc := &association{}
		nm.Add(addr.String(), assoc)

		nm.Del(addr.String())

		assert.Nil(t, nm.Get(addr.String()), "Get should return nil after deleting the entry")
	})
}

// Simulates receiving invalid UDP packets on a server with 100 ciphers.
func BenchmarkUDPUnpackFail(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(100))
	if err != nil {
		b.Fatal(err)
	}
	testPayload := makeTestPayload(50)
	textBuf := make([]byte, serverUDPBufferSize)
	testIP := netip.MustParseAddr("192.0.2.1")
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		findAccessKeyUDP(testIP, textBuf, testPayload, cipherList, noopLogger())
	}
}

// Simulates receiving valid UDP packets from 100 different users, each with
// their own cipher and IP address.
func BenchmarkUDPUnpackRepeat(b *testing.B) {
	const numCiphers = 100 // Must be <256
	cipherList, err := MakeTestCiphers(makeTestSecrets(numCiphers))
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	packets := [numCiphers][]byte{}
	ips := [numCiphers]netip.Addr{}
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	for i, element := range snapshot {
		packets[i] = make([]byte, 0, serverUDPBufferSize)
		plaintext := makeTestPayload(50)
		packets[i], err = shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, element.Value.(*CipherEntry).CryptoKey)
		if err != nil {
			b.Error(err)
		}
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		cipherNumber := n % numCiphers
		ip := ips[cipherNumber]
		packet := packets[cipherNumber]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
		if err != nil {
			b.Error(err)
		}
	}
}

// Simulates receiving valid UDP packets from 100 different IP addresses,
// all using the same cipher.
func BenchmarkUDPUnpackSharedKey(b *testing.B) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1)) // One widely shared key
	if err != nil {
		b.Fatal(err)
	}
	testBuf := make([]byte, serverUDPBufferSize)
	plaintext := makeTestPayload(50)
	snapshot := cipherList.SnapshotForClientIP(netip.Addr{})
	cryptoKey := snapshot[0].Value.(*CipherEntry).CryptoKey
	packet, err := shadowsocks.Pack(make([]byte, serverUDPBufferSize), plaintext, cryptoKey)
	require.Nil(b, err)

	const numIPs = 100 // Must be <256
	ips := [numIPs]netip.Addr{}
	for i := 0; i < numIPs; i++ {
		ips[i] = netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
	}
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ip := ips[n%numIPs]
		_, _, _, err := findAccessKeyUDP(ip, testBuf, packet, cipherList, noopLogger())
		if err != nil {
			b.Error(err)
		}
	}
}

func TestUDPEarlyClose(t *testing.T) {
	cipherList, err := MakeTestCiphers(makeTestSecrets(1))
	if err != nil {
		t.Fatal(err)
	}
	const testTimeout = 200 * time.Millisecond
	handler := NewAssociationHandler(cipherList, &fakeShadowsocksMetrics{})
	handler.SetTargetPacketListener(&packetListener{makePacketConn()})

	clientConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP failed: %v", err)
	}
	require.Nil(t, clientConn.Close())
	// This should return quickly without timing out.
	go PacketServe(clientConn, func(ctx context.Context, conn net.Conn) {
		handler.HandleAssociation(ctx, conn, &fakeUDPAssociationMetrics{})
	}, &natTestMetrics{})
}

// Makes sure the UDP listener returns [io.ErrClosed] on reads and writes after Close().
func TestClosedUDPListenerError(t *testing.T) {
	var packetConn net.PacketConn
	packetConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	err = packetConn.Close()
	require.NoError(t, err)

	_, _, err = packetConn.ReadFrom(nil)
	require.ErrorIs(t, err, net.ErrClosed)

	_, err = packetConn.WriteTo(nil, &net.UDPAddr{})
	require.ErrorIs(t, err, net.ErrClosed)
}
