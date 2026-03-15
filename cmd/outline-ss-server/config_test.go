// Copyright 2024 The Outline Authors
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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Run("InvalidConfig/InvalidListenerType", func(t *testing.T) {
		yaml := `
services:
  - listeners:
    - type:
		- tcp
		- udp
	  address: "[::]:9000"
`

		_, err := readConfig([]byte(yaml))

		require.Error(t, err)
	})

	t.Run("InvalidConfig/UnknownListenerType", func(t *testing.T) {
		yaml := `
services:
  - listeners:
    - type: foo
	  address: "[::]:9000"
`

		_, err := readConfig([]byte(yaml))

		require.Error(t, err)
	})

	t.Run("InvalidConfig", func(t *testing.T) {
		tests := []struct {
			name   string
			yaml   string
			errStr string
		}{
			{
				name: "MissingAddress",
				yaml: `
services:
  - listeners:
    - type: tcp
`,
				errStr: "`address` must be specified",
			},
			{
				name: "InvalidAddress",
				yaml: `
services:
  - listeners:
    - type: tcp
      address: "tcp/[::]:9000"
`,
				errStr: "invalid address",
			},
			{
				name: "HostnameAddress",
				yaml: `
services:
  - listeners:
    - type: tcp
      address: "example.com:9000"
`,
				errStr: "address must be IP",
			},
			{
				name: "WebServerMissingID",
				yaml: `
web:
  servers:
    - listen:
        - "127.0.0.1:8000"
`,
				errStr: "web server must have an ID",
			},
			{
				name: "WebServerInvalidAddress",
				yaml: `
web:
  servers:
    - id: foo
      listen:
        - ":invalid"
`,
				errStr: "invalid listener for web server `foo`",
			},
			{
				name: "WebsocketMissingWebServer",
				yaml: `
services:
  - listeners:
      - type: websocket-stream
        path: "/tcp"
`,
				errStr: "`web_server` must be specified",
			},
			{
				name: "WebsocketMissingPath",
				yaml: `
services:
  - listeners:
      - type: websocket-stream
        web_server: my_web_server
`,
				errStr: "`path` must be specified",
			},
			{
				name: "WebsocketInvalidPath",
				yaml: `
services:
  - listeners:
      - type: websocket-stream
        web_server: my_web_server
        path: "tcp"
`,
				errStr: "`path` must start with `/`",
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				cfg, err := readConfig([]byte(tc.yaml))
				require.NoError(t, err)
				err = cfg.validate()
				require.Error(t, err)
				if !isStrInError(err, tc.errStr) {
					t.Errorf("config validation error=`%v`, expected=`%v`", err, tc.errStr)
				}
			})
		}
	})

	t.Run("ValidConfig", func(t *testing.T) {
		yaml := `
web:
  servers:
    - id: my_web_server
      listen:
        - "127.0.0.1:8000"

services:
  - listeners:
      - type: tcp
        address: "[::]:9000"
      - type: udp
        address: ":9000"
      - type: websocket-stream
        web_server: my_web_server
        path: "/tcp"
    keys:
      - id: user-0
        cipher: chacha20-ietf-poly1305
        secret: Secret0
`
		cfg, err := readConfig([]byte(yaml))
		require.NoError(t, err)
		err = cfg.validate()
		require.NoError(t, err)
	})
}

func TestReadConfig(t *testing.T) {

	t.Run("ExampleFile", func(t *testing.T) {
		config, err := readConfigFile("./config_example.yml")

		require.NoError(t, err)
		expected := Config{
			Web: WebConfig{
				Servers: []WebServerConfig{
					WebServerConfig{ID: "my_web_server", Listeners: []string{"127.0.0.1:8000"}},
				},
			},
			Services: []ServiceConfig{
				ServiceConfig{
					Listeners: []ListenerConfig{
						ListenerConfig{TCP: &TCPUDPConfig{Address: "[::]:9000"}},
						ListenerConfig{UDP: &TCPUDPConfig{Address: "[::]:9000"}},
						ListenerConfig{WebsocketStream: &WebsocketConfig{WebServer: "my_web_server", Path: "/SECRET/tcp"}},
						ListenerConfig{WebsocketPacket: &WebsocketConfig{WebServer: "my_web_server", Path: "/SECRET/udp"}},
					},
					Keys: []KeyConfig{
						KeyConfig{"user-0", "chacha20-ietf-poly1305", "Secret0"},
						KeyConfig{"user-1", "chacha20-ietf-poly1305", "Secret1"},
					},
				},
				ServiceConfig{
					Listeners: []ListenerConfig{
						ListenerConfig{TCP: &TCPUDPConfig{Address: "[::]:9001"}},
						ListenerConfig{UDP: &TCPUDPConfig{Address: "[::]:9001"}},
					},
					Keys: []KeyConfig{
						KeyConfig{"user-2", "chacha20-ietf-poly1305", "Secret2"},
					},
				},
			},
		}
		require.Equal(t, expected, *config)
	})

	t.Run("ParsesDeprecatedFormat", func(t *testing.T) {
		config, err := readConfigFile("./config_example.deprecated.yml")

		require.NoError(t, err)
		expected := Config{
			Keys: []LegacyKeyServiceConfig{
				LegacyKeyServiceConfig{
					KeyConfig: KeyConfig{ID: "user-0", Cipher: "chacha20-ietf-poly1305", Secret: "Secret0"},
					Port:      9000,
				},
				LegacyKeyServiceConfig{
					KeyConfig: KeyConfig{ID: "user-1", Cipher: "chacha20-ietf-poly1305", Secret: "Secret1"},
					Port:      9000,
				},
				LegacyKeyServiceConfig{
					KeyConfig: KeyConfig{ID: "user-2", Cipher: "chacha20-ietf-poly1305", Secret: "Secret2"},
					Port:      9001,
				},
			},
		}
		require.Equal(t, expected, *config)
	})

	t.Run("FromEmptyFile", func(t *testing.T) {
		file, _ := os.CreateTemp("", "empty.yaml")

		config, err := readConfigFile(file.Name())

		require.NoError(t, err)
		require.ElementsMatch(t, Config{}, config)
	})

	t.Run("FromIncorrectFormatFails", func(t *testing.T) {
		file, _ := os.CreateTemp("", "empty.yaml")
		file.WriteString("foo")

		config, err := readConfigFile(file.Name())

		require.Error(t, err)
		require.ElementsMatch(t, Config{}, config)
	})
}

func readConfigFile(filename string) (*Config, error) {
	configData, _ := os.ReadFile(filename)
	return readConfig(configData)
}

func isStrInError(err error, str string) bool {
	return err != nil && strings.Contains(err.Error(), str)
}
