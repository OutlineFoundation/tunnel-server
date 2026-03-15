// Copyright 2019 The Outline Authors
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

package net

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var privateAddressTests = []struct {
	address  string
	expected bool
}{
	{"10.0.2.11", true},
	{"172.16.1.2", true},
	{"172.32.0.0", false},
	{"192.168.0.23", true},
	{"192.169.1.1", false},
	{"127.0.0.1", false},
	{"8.8.8.8", false},
	{"::", false},
	{"fd66:f83a:c650::1", true},
	{"fde4:8dba:82e1::", true},
	{"fe::123", false},
}

func TestIsLanAddress(t *testing.T) {
	for _, tt := range privateAddressTests {
		actual := IsPrivateAddress(net.ParseIP(tt.address))
		if actual != tt.expected {
			t.Errorf("IsLanAddress(%s): expected %t, actual %t", tt.address, tt.expected, actual)
		}
	}
}

func TestRequirePublicIP(t *testing.T) {
	var err error

	assert.Nil(t, RequirePublicIP(net.ParseIP("8.8.8.8")))

	if err := RequirePublicIP(net.ParseIP("2001:4860:4860::8888")); err != nil {
		t.Error(err)
	}

	err = RequirePublicIP(net.ParseIP("192.168.0.23"))
	if assert.NotNil(t, err) {
		var connErr *ConnectionError
		if assert.IsType(t, connErr, err) && assert.True(t, errors.As(err, &connErr)) {
			assert.Equal(t, "ERR_ADDRESS_PRIVATE", connErr.Status)
		}
	}

	err = RequirePublicIP(net.ParseIP("::1"))
	if assert.NotNil(t, err) {
		var connErr *ConnectionError
		if assert.IsType(t, connErr, err) && assert.True(t, errors.As(err, &connErr)) {
			assert.Equal(t, "ERR_ADDRESS_INVALID", connErr.Status)
		}
	}

	err = RequirePublicIP(net.ParseIP("224.0.0.251"))
	if assert.NotNil(t, err) {
		var connErr *ConnectionError
		if assert.IsType(t, connErr, err) && assert.True(t, errors.As(err, &connErr)) {
			assert.Equal(t, "ERR_ADDRESS_INVALID", connErr.Status)
		}
	}

	err = RequirePublicIP(net.ParseIP("ff02::fb"))
	if assert.NotNil(t, err) {
		var connErr *ConnectionError
		if assert.IsType(t, connErr, err) && assert.True(t, errors.As(err, &connErr)) {
			assert.Equal(t, "ERR_ADDRESS_INVALID", connErr.Status)
		}
	}
}

func TestRequirePublicIPInterface(t *testing.T) {
	var err error
	err = RequirePublicIP(net.ParseIP("8.8.8.8"))
	assert.True(t, err == nil)
	assert.Equal(t, nil, err)
}
