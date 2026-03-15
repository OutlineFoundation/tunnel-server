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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"github.com/shadowsocks/go-shadowsocks2/socks"

	"golang.getoutline.org/tunnel-server/internal/slicepool"
	onet "golang.getoutline.org/tunnel-server/net"
)

// NATMetrics is used to report NAT related metrics.
type NATMetrics interface {
	AddNATEntry()
	RemoveNATEntry()
}

// UDPAssociationMetrics is used to report metrics on UDP associations.
type UDPAssociationMetrics interface {
	AddAuthentication(accessKey string)
	AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64)
	AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64)
	AddClose()
}

const (
	// Max UDP buffer size for the server code.
	serverUDPBufferSize = 64 * 1024

	// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
	defaultNatTimeout time.Duration = 5 * time.Minute
)

// Buffer pool used for reading UDP packets.
var readBufPool = slicepool.MakePool(serverUDPBufferSize)

// Wrapper for slog.Debug during UDP proxying.
func debugUDP(l *slog.Logger, msg string, attrs ...slog.Attr) {
	// This is an optimization to reduce unnecessary allocations due to an interaction
	// between Go's inlining/escape analysis and varargs functions like slog.Debug.
	if l.Enabled(nil, slog.LevelDebug) {
		l.LogAttrs(nil, slog.LevelDebug, fmt.Sprintf("UDP: %s", msg), attrs...)
	}
}

// Decrypts src into dst. It tries each cipher until it finds one that authenticates
// correctly. dst and src must not overlap.
func findAccessKeyUDP(clientIP netip.Addr, dst, src []byte, cipherList CipherList, l *slog.Logger) ([]byte, string, *shadowsocks.EncryptionKey, error) {
	// Try each cipher until we find one that authenticates successfully. This assumes that all ciphers are AEAD.
	// We snapshot the list because it may be modified while we use it.
	snapshot := cipherList.SnapshotForClientIP(clientIP)
	for ci, entry := range snapshot {
		id, cryptoKey := entry.Value.(*CipherEntry).ID, entry.Value.(*CipherEntry).CryptoKey
		buf, err := shadowsocks.Unpack(dst, src, cryptoKey)
		if err != nil {
			debugUDP(l, "Failed to unpack.", slog.String("ID", id), slog.Any("err", err))
			continue
		}
		debugUDP(l, "Found cipher.", slog.String("ID", id), slog.Int("index", ci))
		// Move the active cipher to the front, so that the search is quicker next time.
		cipherList.MarkUsedByClientIP(entry, clientIP)
		return buf, id, cryptoKey, nil
	}
	return nil, "", nil, errors.New("could not find valid UDP cipher")
}

type associationHandler struct {
	logger            *slog.Logger
	ciphers           CipherList
	ssm               ShadowsocksConnMetrics
	targetIPValidator onet.TargetIPValidator
	targetListener    transport.PacketListener
}

var _ AssociationHandler = (*associationHandler)(nil)

// NewAssociationHandler creates a Shadowsocks proxy AssociationHandler.
func NewAssociationHandler(cipherList CipherList, ssMetrics ShadowsocksConnMetrics) AssociationHandler {
	if ssMetrics == nil {
		ssMetrics = &NoOpShadowsocksConnMetrics{}
	}
	return &associationHandler{
		logger:            noopLogger(),
		ciphers:           cipherList,
		ssm:               ssMetrics,
		targetIPValidator: onet.RequirePublicIP,
		targetListener:    MakeTargetUDPListener(onet.RequirePublicIP, defaultNatTimeout, 0),
	}
}

// AssociationHandler is a handler that handles UDP assocations.
type AssociationHandler interface {
	HandleAssociation(ctx context.Context, conn net.Conn, assocMetrics UDPAssociationMetrics)
	// SetLogger sets the logger used to log messages. Uses a no-op logger if nil.
	SetLogger(l *slog.Logger)
	// SetTargetPacketListener sets the packet listener to use for target connections.
	SetTargetPacketListener(targetListener transport.PacketListener)
}

func (h *associationHandler) SetLogger(l *slog.Logger) {
	if l == nil {
		l = noopLogger()
	}
	h.logger = l
}

func (h *associationHandler) SetTargetPacketListener(targetListener transport.PacketListener) {
	h.targetListener = targetListener
}

func (h *associationHandler) HandleAssociation(ctx context.Context, clientConn net.Conn, assocMetrics UDPAssociationMetrics) {
	l := h.logger.With(slog.Any("client", clientConn.RemoteAddr()))

	defer func() {
		debugUDP(l, "Done")
		assocMetrics.AddClose()
	}()

	var targetConn net.PacketConn
	var cryptoKey *shadowsocks.EncryptionKey

	readBufLazySlice := readBufPool.LazySlice()
	readBuf := readBufLazySlice.Acquire()
	defer readBufLazySlice.Release()
	for {
		select {
		case <-ctx.Done():
			break
		default:
		}
		clientProxyBytes, err := clientConn.Read(readBuf)
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			debugUDP(l, "Client connection closed")
			break
		}
		pkt := readBuf[:clientProxyBytes]
		debugUDP(l, "Outbound packet.", slog.Int("bytes", clientProxyBytes))

		var proxyTargetBytes int

		connError := func() *onet.ConnectionError {
			// Error from `clientConn.Read()`.
			if err != nil {
				return onet.NewConnectionError("ERR_READ", "Failed to read from association", err)
			}

			var payload []byte
			var tgtAddr net.Addr
			if targetConn == nil {
				ip := clientConn.RemoteAddr().(*net.UDPAddr).AddrPort().Addr()
				var textData []byte
				var keyID string
				textLazySlice := readBufPool.LazySlice()
				unpackStart := time.Now()
				textBuf := textLazySlice.Acquire()
				textData, keyID, cryptoKey, err = findAccessKeyUDP(ip, textBuf, pkt, h.ciphers, h.logger)
				timeToCipher := time.Since(unpackStart)
				h.ssm.AddCipherSearch(err == nil, timeToCipher)

				if err != nil {
					textLazySlice.Release()
					return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack initial packet", err)
				}
				defer textLazySlice.Release()
				assocMetrics.AddAuthentication(keyID)

				var onetErr *onet.ConnectionError
				if payload, tgtAddr, onetErr = h.extractPayloadAndDestination(textData); onetErr != nil {
					return onetErr
				}

				// Create the target connection.
				targetConn, err = h.targetListener.ListenPacket(ctx)
				if err != nil {
					return onet.NewConnectionError("ERR_CREATE_SOCKET", "Failed to create a `PacketConn`", err)
				}
				l = l.With(slog.Any("tgtListener", targetConn.LocalAddr()))
				go func() {
					relayTargetToClient(targetConn, clientConn, cryptoKey, assocMetrics, l)
					clientConn.Close()
				}()
			} else {
				unpackStart := time.Now()
				textData, err := shadowsocks.Unpack(nil, pkt, cryptoKey)
				timeToCipher := time.Since(unpackStart)
				h.ssm.AddCipherSearch(err == nil, timeToCipher)

				if err != nil {
					return onet.NewConnectionError("ERR_CIPHER", "Failed to unpack data from client", err)
				}

				var onetErr *onet.ConnectionError
				if payload, tgtAddr, onetErr = h.extractPayloadAndDestination(textData); onetErr != nil {
					return onetErr
				}
			}

			debugUDP(l, "Proxy exit.")
			proxyTargetBytes, err = targetConn.WriteTo(payload, tgtAddr)
			if err != nil {
				return ensureConnectionError(err, "ERR_WRITE", "Failed to write to target")
			}
			return nil
		}()

		status := "OK"
		if connError != nil {
			debugUDP(l, "Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}
		assocMetrics.AddPacketFromClient(status, int64(clientProxyBytes), int64(proxyTargetBytes))
		if targetConn == nil {
			// If there's still no target connection, we didn't authenticate. Break out of handling the
			// association here so resources can be released.
			break
		}
	}
}

// extractPayloadAndDestination processes a decrypted Shadowsocks UDP packet and
// extracts the payload data and destination address.
func (h *associationHandler) extractPayloadAndDestination(textData []byte) ([]byte, net.Addr, *onet.ConnectionError) {
	tgtAddr := socks.SplitAddr(textData)
	if tgtAddr == nil {
		return nil, nil, onet.NewConnectionError("ERR_READ_ADDRESS", "Failed to get target address", nil)
	}

	tgtUDPAddr, err := transport.MakeNetAddr("udp", tgtAddr.String())
	if err != nil {
		return nil, nil, onet.NewConnectionError("ERR_CONVERT_ADDRESS", fmt.Sprintf("Failed to convert target address %v", tgtAddr), err)
	}

	payload := textData[len(tgtAddr):]
	return payload, tgtUDPAddr, nil
}

type AssociationHandleFunc func(ctx context.Context, conn net.Conn)

// PacketServe listens for UDP packets on the provided [net.PacketConn] and creates
// and manages NAT associations. It uses a NAT map to track active associations and
// handles their lifecycle.
func PacketServe(clientConn net.PacketConn, assocHandle AssociationHandleFunc, metrics NATMetrics) {
	nm := newNATmap()
	ctx, contextCancel := context.WithCancel(context.Background())
	defer contextCancel()

	for {
		lazySlice := readBufPool.LazySlice()
		buffer := lazySlice.Acquire()

		expired := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("Panic in UDP loop. Continuing to listen.", "err", r)
					debug.PrintStack()
					lazySlice.Release()
				}
			}()
			n, clientAddr, err := clientConn.ReadFrom(buffer)
			if err != nil {
				lazySlice.Release()
				if errors.Is(err, net.ErrClosed) {
					expired = true
					return
				}
				slog.Warn("Failed to read from client. Continuing to listen.", "err", err)
				return
			}
			pkt := &packet{payload: buffer[:n], done: lazySlice.Release}

			// TODO(#19): Include server address in the NAT key as well.
			assoc := nm.Get(clientAddr.String())
			if assoc == nil {
				assoc = &association{
					pc:         clientConn,
					clientAddr: clientAddr,
					readCh:     make(chan *packet, 5),
					doneCh:     make(chan struct{}),
				}
				if err != nil {
					slog.Error("Failed to handle association", slog.Any("err", err))
					return
				}

				var existing bool
				assoc, existing = nm.Add(clientAddr.String(), assoc)
				if !existing {
					metrics.AddNATEntry()
					go func() {
						assocHandle(ctx, assoc)
						metrics.RemoveNATEntry()
						_ = assoc.Close()
					}()
				}
			}
			select {
			case <-assoc.doneCh:
				nm.Del(clientAddr.String())
			case assoc.readCh <- pkt:
			default:
				slog.Debug("Dropping packet due to full read queue")
				// TODO: Add a metric to track number of dropped packets.
			}
		}()
		if expired {
			break
		}
	}
}

type packet struct {
	// The contents of the packet.
	payload []byte

	// A function to call as soon as the payload has been consumed. This can be
	// used to release resources.
	done func()
}

// association wraps a [net.PacketConn] with an address into a [net.Conn].
type association struct {
	pc         net.PacketConn
	clientAddr net.Addr
	readCh     chan *packet
	doneCh     chan struct{}
	closeOnce  sync.Once
}

var _ net.Conn = (*association)(nil)

func (a *association) Read(p []byte) (int, error) {
	select {
	case <-a.doneCh:
		return 0, net.ErrClosed
	case pkt := <-a.readCh:
		n := copy(p, pkt.payload)
		pkt.done()
		if n < len(pkt.payload) {
			return n, io.ErrShortBuffer
		}
		return n, nil
	}
}

func (a *association) Write(b []byte) (n int, err error) {
	return a.pc.WriteTo(b, a.clientAddr)
}

func (a *association) Close() error {
	a.closeOnce.Do(func() {
		if a.doneCh != nil {
			close(a.doneCh)
		}
	})
	return nil
}

func (a *association) LocalAddr() net.Addr {
	return a.pc.LocalAddr()
}

func (a *association) RemoteAddr() net.Addr {
	return a.clientAddr
}

func (a *association) SetDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

func (a *association) SetReadDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

func (a *association) SetWriteDeadline(t time.Time) error {
	return errors.ErrUnsupported
}

func isDNS(addr net.Addr) bool {
	_, port, _ := net.SplitHostPort(addr.String())
	return port == "53"
}

type validatingPacketConn struct {
	net.PacketConn
	targetIPValidator onet.TargetIPValidator
}

func (vpc *validatingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
	if err != nil {
		return 0, onet.NewConnectionError("ERR_RESOLVE_ADDRESS", fmt.Sprintf("Failed to resolve target address %v", udpAddr), err)
	}
	if err := vpc.targetIPValidator(udpAddr.IP); err != nil {
		return 0, ensureConnectionError(err, "ERR_ADDRESS_INVALID", "invalid address")
	}

	return vpc.PacketConn.WriteTo(p, udpAddr) // accept only `net.UDPAddr` despite the signature
}

type timedPacketConn struct {
	net.PacketConn
	// Connection timeout to apply for non-DNS packets.
	defaultTimeout time.Duration
	// Current read deadline of PacketConn.  Used to avoid decreasing the
	// deadline.  Initially zero.
	readDeadline time.Time
	// If the connection has only sent one DNS query, it will close
	// if it receives a DNS response.
	fastClose sync.Once
}

func (c *timedPacketConn) onWrite(addr net.Addr) {
	// Fast close is only allowed if there has been exactly one write,
	// and it was a DNS query.
	isDNS := isDNS(addr)
	isFirstWrite := c.readDeadline.IsZero()
	if !isDNS || !isFirstWrite {
		// Disable fast close.  (Idempotent.)
		c.fastClose.Do(func() {})
	}

	timeout := c.defaultTimeout
	if isDNS {
		// Shorten timeout as required by RFC 5452 Section 10.
		timeout = 17 * time.Second
	}

	newDeadline := time.Now().Add(timeout)
	if newDeadline.After(c.readDeadline) {
		c.readDeadline = newDeadline
		c.SetReadDeadline(newDeadline)
	}
}

func (c *timedPacketConn) onRead(addr net.Addr) {
	c.fastClose.Do(func() {
		if isDNS(addr) {
			// The next ReadFrom() should time out immediately.
			c.SetReadDeadline(time.Now())
		}
	})
}

func (c *timedPacketConn) WriteTo(buf []byte, dst net.Addr) (int, error) {
	c.onWrite(dst)
	return c.PacketConn.WriteTo(buf, dst)
}

func (c *timedPacketConn) ReadFrom(buf []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(buf)
	if err == nil {
		c.onRead(addr)
	}
	return n, addr, err
}

// Packet NAT table
type natmap struct {
	sync.RWMutex
	associations map[string]*association
}

func newNATmap() *natmap {
	return &natmap{associations: make(map[string]*association)}
}

// Get returns a UDP NAT entry from the natmap.
func (m *natmap) Get(clientAddr string) *association {
	m.RLock()
	defer m.RUnlock()
	return m.associations[clientAddr]
}

// Del deletes a UDP NAT entry from the natmap.
func (m *natmap) Del(clientAddr string) {
	m.Lock()
	defer m.Unlock()

	if _, ok := m.associations[clientAddr]; ok {
		delete(m.associations, clientAddr)
	}
}

// Add adds a UDP NAT entry to the natmap and returns it. If it already existed,
// in the natmap, the existing entry is returned instead.
func (m *natmap) Add(clientAddr string, assoc *association) (*association, bool) {
	m.Lock()
	defer m.Unlock()

	if existing, ok := m.associations[clientAddr]; ok {
		return existing, true
	}

	m.associations[clientAddr] = assoc
	return assoc, false
}

// Get the maximum length of the shadowsocks address header by parsing
// and serializing an IPv6 address from the example range.
var maxAddrLen int = len(socks.ParseAddr("[2001:db8::1]:12345"))

// relayTargetToClient copies from target to client until read timeout.
func relayTargetToClient(targetConn net.PacketConn, clientConn io.Writer, cryptoKey *shadowsocks.EncryptionKey, m UDPAssociationMetrics, l *slog.Logger) {
	defer targetConn.Close()

	// pkt is used for in-place encryption of downstream UDP packets, with the layout
	// [padding?][salt][address][body][tag][extra]
	// Padding is only used if the address is IPv4.
	pkt := make([]byte, serverUDPBufferSize)

	saltSize := cryptoKey.SaltSize()
	// Leave enough room at the beginning of the packet for a max-length header (i.e. IPv6).
	bodyStart := saltSize + maxAddrLen

	expired := false
	for {
		var targetProxyBytes, proxyClientBytes int
		connError := func() *onet.ConnectionError {
			var (
				raddr net.Addr
				err   error
			)
			// `readBuf` receives the plaintext body in `pkt`:
			// [padding?][salt][address][body][tag][unused]
			// |--     bodyStart     --|[      readBuf    ]
			readBuf := pkt[bodyStart:]
			targetProxyBytes, raddr, err = targetConn.ReadFrom(readBuf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok {
					if netErr.Timeout() {
						expired = true
						return nil
					}
				}
				return onet.NewConnectionError("ERR_READ", "Failed to read from target", err)
			}

			debugUDP(l, "Got response.", slog.Any("rtarget", raddr))
			srcAddr := socks.ParseAddr(raddr.String())
			addrStart := bodyStart - len(srcAddr)
			// `plainTextBuf` concatenates the SOCKS address and body:
			// [padding?][salt][address][body][tag][unused]
			// |-- addrStart -|[plaintextBuf ]
			plaintextBuf := pkt[addrStart : bodyStart+targetProxyBytes]
			copy(plaintextBuf, srcAddr)

			// saltStart is 0 if raddr is IPv6.
			saltStart := addrStart - saltSize
			// `packBuf` adds space for the salt and tag.
			// `buf` shows the space that was used.
			// [padding?][salt][address][body][tag][unused]
			//           [            packBuf             ]
			//           [          buf           ]
			packBuf := pkt[saltStart:]
			buf, err := shadowsocks.Pack(packBuf, plaintextBuf, cryptoKey) // Encrypt in-place
			if err != nil {
				return onet.NewConnectionError("ERR_PACK", "Failed to pack data to client", err)
			}
			proxyClientBytes, err = clientConn.Write(buf)
			if err != nil {
				return onet.NewConnectionError("ERR_WRITE", "Failed to write to client", err)
			}
			return nil
		}()
		status := "OK"
		if connError != nil {
			debugUDP(l, "Error", slog.String("msg", connError.Message), slog.Any("cause", connError.Cause))
			status = connError.Status
		}

		if expired {
			break
		}
		m.AddPacketFromTarget(status, int64(targetProxyBytes), int64(proxyClientBytes))
	}
}

// NoOpUDPAssociationMetrics is a [UDPAssociationMetrics] that doesn't do anything. Useful in tests
// or if you don't want to track metrics.
type NoOpUDPAssociationMetrics struct{}

var _ UDPAssociationMetrics = (*NoOpUDPAssociationMetrics)(nil)

func (m *NoOpUDPAssociationMetrics) AddAuthentication(accessKey string) {}

func (m *NoOpUDPAssociationMetrics) AddPacketFromClient(status string, clientProxyBytes, proxyTargetBytes int64) {
}
func (m *NoOpUDPAssociationMetrics) AddPacketFromTarget(status string, targetProxyBytes, proxyClientBytes int64) {
}
func (m *NoOpUDPAssociationMetrics) AddClose() {
}
