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
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/prometheus/client_golang/prometheus"

	"golang.getoutline.org/tunnel-server/ipinfo"
	outline_prometheus "golang.getoutline.org/tunnel-server/prometheus"
	outline "golang.getoutline.org/tunnel-server/service"
)

const (
	outlineModuleName              = "outline"
	replayCacheCtxKey caddy.CtxKey = "outline.replay_cache"
	metricsCtxKey     caddy.CtxKey = "outline.metrics"
)

func init() {
	replayCache := outline.NewReplayCache(0)

	// ipInfoPool uses *caddy.UsagePool (reference counter) to allow
	// transparent ipinfo sharing across reloads.
	ipInfoPool := caddy.NewUsagePool()

	caddy.RegisterModule(ModuleRegistration{
		ID: outlineModuleName,
		New: func() caddy.Module {
			app := new(OutlineApp)
			app.replayCache = &replayCache
			app.ipInfoPool = ipInfoPool
			return app
		},
	})
}

// ipInfoKey contains asn / country db paths and last modification time.
// We can use this key as reference between caddy reloads: if one of the database
// has been updated, reload them.
type ipInfoKey struct {
	// countryDBPath the path to country database file.
	countryDBPath string
	// countryDBMod contains the last modification time of countryDBPath.
	countryDBMod int64

	// asnDBPath the path to ASN database file.
	asnDBPath string
	// asnDBMod contains the last modification time of asnDBPath.
	asnDBMod int64
}

// sharedIPInfo must implement `caddy.Destructor`
type sharedIPInfo struct{ *ipinfo.MMDBIPInfoMap }

func (s sharedIPInfo) Destruct() error {
	return s.Close()
}

type IPInfoConfig struct {
	CountryDB string `json:"country_database,omitempty"`
	ASNDB     string `json:"asn_database,omitempty"`
}

type ShadowsocksConfig struct {
	ReplayHistory int `json:"replay_history,omitempty"`
}

type OutlineApp struct {
	ShadowsocksConfig *ShadowsocksConfig `json:"shadowsocks,omitempty"`
	Handlers          ConnectionHandlers `json:"connection_handlers,omitempty"`
	IPInfoConfig      *IPInfoConfig      `json:"ipinfo,omitempty"`

	logger      *slog.Logger
	replayCache *outline.ReplayCache
	metrics     outline.ServiceMetrics
	buildInfo   *prometheus.GaugeVec

	ipInfoPool *caddy.UsagePool
	ipInfo     ipinfo.IPInfoMap
	ipInfoKey  *ipInfoKey
}

var (
	_ caddy.App          = (*OutlineApp)(nil)
	_ caddy.Provisioner  = (*OutlineApp)(nil)
	_ caddy.CleanerUpper = (*OutlineApp)(nil)
	_ caddy.Destructor   = sharedIPInfo{}
)

func (OutlineApp) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: outlineModuleName}
}

// Provision sets up Outline.
func (app *OutlineApp) Provision(ctx caddy.Context) error {
	app.logger = ctx.Slogger()

	app.logger.Info("provisioning app instance")

	// Only validate the replay history here. The shared replay cache is resized
	// in Start(), once the whole replacement config has provisioned successfully;
	// resizing it here would alter replay protection for the currently running
	// app if a later provisioning step fails and the reload is rejected.
	if app.ShadowsocksConfig != nil && app.ShadowsocksConfig.ReplayHistory > outline.MaxCapacity {
		return fmt.Errorf("replay history capacity %d exceeds the maximum of %d", app.ShadowsocksConfig.ReplayHistory, outline.MaxCapacity)
	}

	// Provision the app with ip info databases.
	// Do not return an error here: if an initial `ipinfo` config is valid,
	// but a new one after a reload is not, the server will stay running with the old config.
	app.provisionIPInfo()

	if err := app.defineMetrics(ctx.GetMetricsRegistry()); err != nil {
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

// statDB returns the modification time of a database file, or ok=false if the
// path is unusable. Unusable databases are logged and skipped, not fatal.
func (app *OutlineApp) statDB(kind, path string) (int64, bool) {
	st, err := os.Stat(path)
	if err == nil && st.IsDir() {
		err = errors.New("path is a directory, want a file")
	}

	if err != nil {
		app.logger.Error(
			"failed to load IP info database",
			"database", kind,
			"path", path,
			"err", err,
		)
		return 0, false
	}

	return st.ModTime().UnixMicro(), true
}

func (app *OutlineApp) provisionIPInfo() {
	if app.IPInfoConfig == nil {
		return
	}

	if app.ipInfoPool == nil {
		app.logger.Error("IP info pool not configured, skipping IP info database")
		return
	}

	key := ipInfoKey{}

	// Country database
	if p := app.IPInfoConfig.CountryDB; len(p) > 0 {
		if mod, ok := app.statDB("country", p); ok {
			key.countryDBPath = p
			key.countryDBMod = mod
		}
	}

	// ASN database
	if p := app.IPInfoConfig.ASNDB; len(p) > 0 {
		if mod, ok := app.statDB("asn", p); ok {
			key.asnDBPath = p
			key.asnDBMod = mod
		}
	}

	if key == (ipInfoKey{}) {
		return
	}

	v, _, err := app.ipInfoPool.LoadOrNew(key, func() (caddy.Destructor, error) {
		m, err := ipinfo.NewMMDBIPInfoMap(key.countryDBPath, key.asnDBPath)
		if err != nil {
			return nil, err
		}

		return sharedIPInfo{m}, nil
	})
	if err != nil {
		app.logger.Error(
			"failed to open IP info databases, IP location metrics disabled",
			"country", key.countryDBPath,
			"asn", key.asnDBPath,
			"err", err,
		)
		return
	}

	app.ipInfo = v.(sharedIPInfo)
	app.ipInfoKey = &key

	app.logger.Info("IP info database configured", "country", key.countryDBPath, "asn", key.asnDBPath)
}

func (app *OutlineApp) defineMetrics(metricsRegistry prometheus.Registerer) error {
	r := prometheus.WrapRegistererWithPrefix("outline_", metricsRegistry)

	var err error
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "build_info",
		Help: "Information on the outline-ss-server build",
	}, []string{"version"})
	app.buildInfo, err = registerCollector(r, buildInfo)
	if err != nil {
		return err
	}

	metrics, err := outline_prometheus.NewServiceMetrics(app.ipInfo)
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
	if app.ShadowsocksConfig != nil {
		if err := app.replayCache.Resize(app.ShadowsocksConfig.ReplayHistory); err != nil {
			return fmt.Errorf("failed to configure replay history with capacity %d: %v", app.ShadowsocksConfig.ReplayHistory, err)
		}
	}
	app.logger.Debug("started app instance")
	return nil
}

// Stop stops the App.
func (app *OutlineApp) Stop() error {
	app.logger.Debug("stopped app instance")
	return nil
}

// Cleanup releases the shared IP info database.
// It may run without Start or Stop.
func (app *OutlineApp) Cleanup() error {
	app.logger.Debug("app instance cleanup")

	if app.ipInfoKey == nil {
		return nil
	}

	_, err := app.ipInfoPool.Delete(*app.ipInfoKey)
	app.ipInfo = nil
	app.ipInfoKey = nil

	return err
}
