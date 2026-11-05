// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package outlinecaddy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/websocket"
)

// unwrapOnlyResponseWriter mimics the writers Caddy hands to handlers since
// v2.11.5: the underlying connection is reachable through Unwrap (and thus
// http.ResponseController) but the writer does not implement http.Hijacker.
type unwrapOnlyResponseWriter struct {
	http.ResponseWriter
}

func (w unwrapOnlyResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func newTestWebSocketHandler(t *testing.T, next layer4.NextHandler) *WebSocketHandler {
	t.Helper()

	return &WebSocketHandler{
		Type:            StreamConnectionType,
		compiledHandler: next,
		logger:          slog.New(slog.DiscardHandler),
		zlogger:         zap.NewNop(),
	}
}

func TestWebSocketHandler_UpgradeThroughWrappedWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		wrap func(http.ResponseWriter) http.ResponseWriter
	}{
		{"writer implements Hijacker", func(w http.ResponseWriter) http.ResponseWriter { return w }},
		{"writer only implements Unwrap", func(w http.ResponseWriter) http.ResponseWriter {
			return unwrapOnlyResponseWriter{ResponseWriter: w}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var handled atomic.Int32

			echo := layer4.NextHandlerFunc(func(cx *layer4.Connection, _ layer4.Handler) error {
				handled.Add(1)
				if got := cx.GetVar(outlineConnectionTypeCtxKey); got != StreamConnectionType {
					t.Errorf("connection type var = %v, want %v", got, StreamConnectionType)
				}
				_, err := io.Copy(cx, cx)
				return err
			})

			h := newTestWebSocketHandler(t, echo)

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := h.ServeHTTP(tc.wrap(w), r, nil); err != nil {
					t.Errorf("ServeHTTP() error = %v", err)
				}
			}))
			defer srv.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			addr := strings.TrimPrefix(srv.URL, "http://")

			connect, err := websocket.NewStreamEndpoint("ws://"+addr+"/tcp", &transport.TCPEndpoint{Address: addr})
			if err != nil {
				t.Fatalf("NewStreamEndpoint() error = %v", err)
			}

			conn, err := connect(ctx)
			if err != nil {
				t.Fatalf("websocket upgrade failed: %v", err)
			}
			defer conn.Close()

			want := bytes.Repeat([]byte("outline"), 1000)
			if _, err := conn.Write(want); err != nil {
				t.Fatalf("Write() error = %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, len(want))

			if _, err := io.ReadFull(conn, got); err != nil {
				t.Fatalf("ReadFull() error = %v", err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("echo mismatch: got %d bytes, want %d", len(got), len(want))
			}

			if handled.Load() != 1 {
				t.Fatalf("connection handler invoked %d times, want 1", handled.Load())
			}
		})
	}
}

func TestWebSocketHandler_RejectsNonUpgradeRequest(t *testing.T) {
	var handled atomic.Int32

	h := newTestWebSocketHandler(t, layer4.NextHandlerFunc(func(*layer4.Connection, layer4.Handler) error {
		handled.Add(1)
		return nil
	}))

	rec := httptest.NewRecorder() // Implements neither Hijacker nor Unwrap.
	req := httptest.NewRequest(http.MethodGet, "/tcp", nil)

	if err := h.ServeHTTP(rec, req, nil); err != nil {
		t.Fatalf("ServeHTTP() error = %v, want nil", err)
	}

	if rec.Code < http.StatusBadRequest {
		t.Errorf("status = %d, want a client or server error", rec.Code)
	}

	if handled.Load() != 0 {
		t.Errorf("connection handler invoked %d times, want 0", handled.Load())
	}
}
