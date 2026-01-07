// Copyright 2023 The Outline Authors
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
	"net"
	"strings"
	"testing"
	"time"

	"golang.getoutline.org/tunnel-server/ipinfo"
	"github.com/op/go-logging"
	"github.com/prometheus/client_golang/prometheus"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

type noopMap struct{}

func (*noopMap) GetIPInfo(ip net.IP) (ipinfo.IPInfo, error) {
	return ipinfo.IPInfo{}, nil
}

type fakeAddr string

func (a fakeAddr) String() string  { return string(a) }
func (a fakeAddr) Network() string { return "" }

// Sets the processing clock to be t until changed.
func setNow(t time.Time) {
	now = func() time.Time {
		return t
	}
}

func init() {
	logging.SetLevel(logging.INFO, "")
}

type fakeConn struct {
	net.Conn
}

func (c *fakeConn) LocalAddr() net.Addr {
	return fakeAddr("127.0.0.1:9")
}

func (c *fakeConn) RemoteAddr() net.Addr {
	return fakeAddr("127.0.0.1:10")
}

func TestMethodsDontPanic(t *testing.T) {
	m := newPrometheusServerMetrics()
	m.SetVersion("0.0.0-test")
	m.SetNumAccessKeys(20, 2)
}

func TestSetVersion(t *testing.T) {
	m := newPrometheusServerMetrics()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m)

	m.SetVersion("0.0.0-test")

	err := promtest.GatherAndCompare(
		reg,
		strings.NewReader(`
			# HELP build_info Information on the outline-ss-server build
			# TYPE build_info gauge
			build_info{version="0.0.0-test"} 1
		`),
		"build_info",
	)
	require.NoError(t, err, "unexpected metric value found")
}

func TestSetNumAccessKeys(t *testing.T) {
	m := newPrometheusServerMetrics()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(m)

	m.SetNumAccessKeys(1, 2)

	err := promtest.GatherAndCompare(
		reg,
		strings.NewReader(`
			# HELP keys Count of access keys
			# TYPE keys gauge
			keys 1
			# HELP ports Count of open ports
			# TYPE ports gauge
			ports 2
		`),
		"keys",
		"ports",
	)
	require.NoError(t, err, "unexpected metric value found")
}
