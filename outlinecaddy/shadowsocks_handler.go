// Copyright 2024 The Outline Authors
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
	"container/list"
	"fmt"
	"log/slog"
	"time"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/transport/shadowsocks"
	"github.com/caddyserver/caddy/v2"
	"github.com/mholt/caddy-l4/layer4"

	outline "golang.getoutline.org/tunnel-server/service"
)

const ssModuleName = "layer4.handlers.shadowsocks"

// A UDP NAT timeout of at least 5 minutes is recommended in RFC 4787 Section 4.3.
const defaultNatTimeout time.Duration = 5 * time.Minute

func init() {
	caddy.RegisterModule(ModuleRegistration{
		ID:  ssModuleName,
		New: func() caddy.Module { return new(ShadowsocksHandler) },
	})
}

type KeyConfig struct {
	ID     string
	Cipher string
	Secret string
}

// ShadowsocksHandler implements a Caddy plugin for handling Outline Shadowsocks
// connections.
//
// It manages Shadowsocks encryption keys, creates the necessary
// [outline.StreamHandler] or [outline.AssociationHandler], and dispatches
// connections to the appropriate handler based on the connection type (stream
// or packet).
type ShadowsocksHandler struct {
	Keys []KeyConfig `json:"keys,omitempty"`

	streamHandler      outline.StreamHandler
	associationHandler outline.AssociationHandler
	metrics            outline.ServiceMetrics
	logger             *slog.Logger
}

var (
	_ caddy.Provisioner  = (*ShadowsocksHandler)(nil)
	_ layer4.NextHandler = (*ShadowsocksHandler)(nil)
)

func (*ShadowsocksHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: ssModuleName}
}

// Provision implements caddy.Provisioner.
func (h *ShadowsocksHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Slogger()

	if len(h.Keys) == 0 {
		h.logger.Warn("no keys configured")
	}
	type cipherKey struct {
		cipher string
		secret string
	}
	cipherList := list.New()
	existingCiphers := make(map[cipherKey]bool)
	for _, cfg := range h.Keys {
		key := cipherKey{cfg.Cipher, cfg.Secret}
		if _, exists := existingCiphers[key]; exists {
			h.logger.Debug("Encryption key already exists. Skipping.", slog.String("id", cfg.ID))
			continue
		}
		cryptoKey, err := shadowsocks.NewEncryptionKey(cfg.Cipher, cfg.Secret)
		if err != nil {
			return fmt.Errorf("failed to create encyption key for key %v: %w", cfg.ID, err)
		}
		entry := outline.MakeCipherEntry(cfg.ID, cryptoKey, cfg.Secret)
		cipherList.PushBack(&entry)
		existingCiphers[key] = true
	}
	ciphers := outline.NewCipherList()
	ciphers.Update(cipherList)

	replayCache, ok := ctx.Value(replayCacheCtxKey).(outline.ReplayCache)
	if !ok {
		h.logger.Warn("Handler configured outside Outline app; replay cache not available.")
	}
	h.metrics, ok = ctx.Value(metricsCtxKey).(outline.ServiceMetrics)
	if !ok {
		h.logger.Warn("Handler configured outside Outline app; metrics not available.")
	}

	h.streamHandler, h.associationHandler = outline.NewShadowsocksHandlers(
		outline.WithLogger(h.logger),
		outline.WithCiphers(ciphers),
		outline.WithMetrics(h.metrics),
		outline.WithReplayCache(&replayCache),
	)
	return nil
}

// Handle implements layer4.NextHandler.
func (h *ShadowsocksHandler) Handle(cx *layer4.Connection, _ layer4.Handler) error {
	connType, ok := cx.GetVar(outlineConnectionTypeCtxKey).(ConnectionType)
	if !ok {
		// Likely if the Shadowsocks handler was used directly instead of through
		// the Outline connection handler.
		return fmt.Errorf("unknown outline connection type")
	}

	switch connType {
	case StreamConnectionType:
		h.streamHandler.HandleStream(cx.Context, cx.Conn.(transport.StreamConn), h.metrics.AddOpenTCPConnection(cx))
	case PacketConnectionType:
		h.associationHandler.HandleAssociation(cx.Context, cx.Conn, h.metrics.AddOpenUDPAssociation(cx))
	}
	return nil
}
