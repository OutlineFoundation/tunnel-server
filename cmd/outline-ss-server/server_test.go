// Copyright 2020 The Outline Authors
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
	"testing"
	"time"

	"golang.getoutline.org/tunnel-server/prometheus"
)

func TestRunOutlineServer(t *testing.T) {
	serverMetrics := newPrometheusServerMetrics()
	serviceMetrics, err := prometheus.NewServiceMetrics(nil)
	if err != nil {
		t.Fatalf("Failed to create Prometheus service metrics: %v", err)
	}
	server, err := RunOutlineServer("config_example.yml", 30*time.Second, serverMetrics, serviceMetrics, 10000)
	if err != nil {
		t.Fatalf("RunOutlineServer() error = %v", err)
	}
	if err := server.Stop(); err != nil {
		t.Errorf("Error while stopping server: %v", err)
	}
}
