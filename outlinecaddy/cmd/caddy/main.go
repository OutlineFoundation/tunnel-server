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

// The `nomysql` build tag excludes MySQL drivers from the Caddy binary,
// avoiding the inclusion of MPL-2 licensed code. See
// https://github.com/caddyserver/caddy/issues/6613.
//
//go:build nomysql
// +build nomysql

package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "golang.getoutline.org/tunnel-server/outlinecaddy"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/iamd3vil/caddy_yaml_adapter"
	_ "github.com/mholt/caddy-l4"
	_ "github.com/mholt/caddy-l4/layer4"
	_ "github.com/mholt/caddy-l4/modules/l4http"
)

func main() {
	caddycmd.Main()
}
