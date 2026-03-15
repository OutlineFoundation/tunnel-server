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
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"
)

type Validator interface {
	// Validate checks that the type is valid.
	validate() error
}

type ServiceConfig struct {
	Listeners []ListenerConfig
	Keys      []KeyConfig
	Dialer    DialerConfig
}

type ListenerType string

const (
	TCPListenerType             = ListenerType("tcp")
	UDPListenerType             = ListenerType("udp")
	WebsocketStreamListenerType = ListenerType("websocket-stream")
	WebsocketPacketListenerType = ListenerType("websocket-packet")
)

type WebServerConfig struct {
	// Unique identifier of the web server to be referenced in Websocket connections.
	ID string

	// List of listener addresses (e.g., ":8080", "localhost:8081"). Should be localhost for HTTP.
	Listeners []string `yaml:"listen"`
}

// ListenerConfig holds the configuration for a listener.  It supports different
// listener types, configured via the embedded type and unmarshalled based on
// the "type" field in the YAML/JSON configuration. Only one of the fields will
// be set, corresponding to the listener type.
type ListenerConfig struct {
	// TCP configuration for the listener.
	TCP *TCPUDPConfig
	// UDP configuration for the listener.
	UDP *TCPUDPConfig
	// Websocket stream configuration for the listener.
	WebsocketStream *WebsocketConfig
	// Websocket packet configuration for the listener.
	WebsocketPacket *WebsocketConfig
}

var _ Validator = (*ListenerConfig)(nil)
var _ yaml.Unmarshaler = (*ListenerConfig)(nil)

// Define a map to associate listener types with [ListenerConfig] field names.
var listenerTypeMap = map[ListenerType]string{
	TCPListenerType:             "TCP",
	UDPListenerType:             "UDP",
	WebsocketStreamListenerType: "WebsocketStream",
	WebsocketPacketListenerType: "WebsocketPacket",
}

func (c *ListenerConfig) UnmarshalYAML(value *yaml.Node) error {
	var raw map[string]interface{}
	if err := value.Decode(&raw); err != nil {
		return err
	}

	// Remove the "type" field so we can decode directly into the target struct.
	rawType, ok := raw["type"]
	if !ok {
		return errors.New("`type` field required")
	}
	lnTypeStr, ok := rawType.(string)
	if !ok {
		return fmt.Errorf("`type` is not a string, but %T", rawType)	
	}
	lnType := ListenerType(lnTypeStr)
	delete(raw, "type")

	fieldName, ok := listenerTypeMap[lnType]
	if !ok {
		return fmt.Errorf("invalid listener type: %v", lnType)
	}
	v := reflect.ValueOf(c).Elem()
	field := v.FieldByName(fieldName)
	if !field.IsValid() {
		return fmt.Errorf("invalid field name: %s for type: %s", fieldName, lnType)
	}
	fieldType := field.Type()
	if fieldType.Kind() != reflect.Ptr || fieldType.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("field %s is not a pointer to a struct", fieldName)
	}

	configValue := reflect.New(fieldType.Elem())
	field.Set(configValue)
	if err := mapstructure.Decode(raw, configValue.Interface()); err != nil {
		return fmt.Errorf("failed to decode map: %w", err)
	}
	return nil
}

func (c *ListenerConfig) validate() error {
	v := reflect.ValueOf(c).Elem()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if field.Kind() == reflect.Ptr && field.IsNil() {
			continue
		}
		if validator, ok := field.Interface().(Validator); ok {
			if err := validator.validate(); err != nil {
				return fmt.Errorf("invalid config: %v", err)
			}
		}
	}
	return nil
}

type TCPUDPConfig struct {
	// Address for the TCP or UDP listener.  Should be in the format host:port.
	Address string
}

var _ Validator = (*TCPUDPConfig)(nil)

func (c *TCPUDPConfig) validate() error {
	if c.Address == "" {
		return errors.New("`address` must be specified")
	}
	if err := validateAddress(c.Address); err != nil {
		return fmt.Errorf("invalid address: %v", err)
	}
	return nil
}

type WebsocketConfig struct {
	// Web server unique identifier to use for the websocket connection.
	WebServer string `mapstructure:"web_server"`
	// Path for the websocket connection.
	Path string
}

var _ Validator = (*WebsocketConfig)(nil)

func (c *WebsocketConfig) validate() error {
	if c.WebServer == "" {
		return errors.New("`web_server` must be specified")
	}
	if c.Path == "" {
		return errors.New("`path` must be specified")
	}
	if !strings.HasPrefix(c.Path, "/") {
		return errors.New("`path` must start with `/`")
	}
	return nil
}

type DialerConfig struct {
	Fwmark uint
}

type KeyConfig struct {
	ID     string
	Cipher string
	Secret string
}

type LegacyKeyServiceConfig struct {
	KeyConfig `yaml:",inline"`
	Port      int
}

type WebConfig struct {
	Servers []WebServerConfig `yaml:"servers"`
}

type Config struct {
	Web      WebConfig
	Services []ServiceConfig

	// Deprecated: `keys` exists for backward compatibility. Prefer to configure
	// using the newer `services` format.
	Keys []LegacyKeyServiceConfig
}

var _ Validator = (*Config)(nil)

func (c *Config) validate() error {
	for _, srv := range c.Web.Servers {
		if srv.ID == "" {
			return fmt.Errorf("web server must have an ID")
		}
		for _, addr := range srv.Listeners {
			if err := validateAddress(addr); err != nil {
				return fmt.Errorf("invalid listener for web server `%s`: %w", srv.ID, err)
			}
		}
	}

	for _, service := range c.Services {
		for _, ln := range service.Listeners {
			if err := ln.validate(); err != nil {
				return fmt.Errorf("invalid listener: %v", err)
			}
		}
	}
	return nil
}

func validateAddress(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	// NOTE: We allow addresses with only the port number set . This will result
	// in an address that listens on all available network interfaces (both IPv4
	// and IPv6).
	if host != "" {
		if ip := net.ParseIP(host); ip == nil {
			return fmt.Errorf("address must be IP, found: %s", host)
		}
	}
	if portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port: %s", portStr)
		}
		if port < 0 || port > 65535 {
			return fmt.Errorf("port out of range: %d", port)
		}
	}
	return nil
}

// readConfig attempts to read a config from a filename and parses it as a [Config].
func readConfig(configData []byte) (*Config, error) {
	config := Config{}
	if err := yaml.Unmarshal(configData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	return &config, nil
}
