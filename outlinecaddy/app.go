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

// Package caddy provides an app and handler for Caddy Server (https://caddyserver.com/)
// allowing it to turn any handler into one supporting the Vulcain protocol.

package outlinecaddy

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"

	outline_prometheus "golang.getoutline.org/tunnel-server/prometheus"
	outline "golang.getoutline.org/tunnel-server/service"
	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	outlineModuleName              = "outline"
	replayCacheCtxKey caddy.CtxKey = "outline.replay_cache"
	metricsCtxKey     caddy.CtxKey = "outline.metrics"
)

func init() {
	replayCache := outline.NewReplayCache(0)
	caddy.RegisterModule(ModuleRegistration{
		ID: outlineModuleName,
		New: func() caddy.Module {
			app := new(OutlineApp)
			app.replayCache = replayCache
			return app
		},
	})
}

type ShadowsocksConfig struct {
	ReplayHistory int `json:"replay_history,omitempty"`
}

type OutlineApp struct {
	ShadowsocksConfig *ShadowsocksConfig `json:"shadowsocks,omitempty"`
	Handlers          ConnectionHandlers `json:"connection_handlers,omitempty"`

	logger      *slog.Logger
	replayCache outline.ReplayCache
	metrics     outline.ServiceMetrics
	buildInfo   *prometheus.GaugeVec
}

var (
	_ caddy.App         = (*OutlineApp)(nil)
	_ caddy.Provisioner = (*OutlineApp)(nil)
)

func (OutlineApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: outlineModuleName}
}

// Provision sets up Outline.
func (app *OutlineApp) Provision(ctx caddy.Context) error {
	app.logger = ctx.Slogger()

	app.logger.Info("provisioning app instance")

	if app.ShadowsocksConfig != nil {
		if err := app.replayCache.Resize(app.ShadowsocksConfig.ReplayHistory); err != nil {
			return fmt.Errorf("failed to configure replay history with capacity %d: %v", app.ShadowsocksConfig.ReplayHistory, err)
		}
	}

	if err := app.defineMetrics(); err != nil {
		app.logger.Error("failed to define Prometheus metrics", "err", err)
	}
	// TODO: Set version at build time.
	app.buildInfo.WithLabelValues("dev").Set(1)
	// TODO: Add replacement metrics for `shadowsocks_keys` and `shadowsocks_ports`.

	ctx = ctx.WithValue(replayCacheCtxKey, app.replayCache)
	ctx = ctx.WithValue(metricsCtxKey, app.metrics)

	err := app.Handlers.Provision(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (app *OutlineApp) defineMetrics() error {
	r := prometheus.WrapRegistererWithPrefix("outline_", prometheus.DefaultRegisterer)

	var err error
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_info",
		Help: "Information on the outline-ss-server build",
	}, []string{"version"})
	app.buildInfo, err = registerCollector(r, buildInfo)
	if err != nil {
		return err
	}

	// TODO: Allow the configuration of ip2info.
	metrics, err := outline_prometheus.NewServiceMetrics(nil)
	if err != nil {
		return err
	}
	app.metrics, err = registerCollector(r, metrics)
	if err != nil {
		return err
	}
	return nil
}

func registerCollector[T prometheus.Collector](registerer prometheus.Registerer, coll T) (T, error) {
	if err := registerer.Register(coll); err != nil {
		are := &prometheus.AlreadyRegisteredError{}
		dupeErr := strings.Contains(err.Error(), "duplicate metrics collector registration attempted")
		if !errors.As(err, are) || dupeErr {
			// This collector has been registered before. This is expected during a config reload.
			coll = are.ExistingCollector.(T)
		} else {
			// Something else went wrong.
			return coll, err
		}
	}
	return coll, nil
}

// Start starts the App.
func (app *OutlineApp) Start() error {
	app.logger.Debug("started app instance")
	return nil
}

// Stop stops the App.
func (app *OutlineApp) Stop() error {
	app.logger.Debug("stopped app instance")
	return nil
}
