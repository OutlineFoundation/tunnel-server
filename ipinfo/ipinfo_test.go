// Copyright 2023 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipinfo

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type noopMap struct{}

func (*noopMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	return IPInfo{}, nil
}

type badMap struct{}

func (*badMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	return IPInfo{}, errors.New("bad map")
}

type badAddr struct {
	address string
}

func (a *badAddr) String() string {
	return a.address
}

func (a *badAddr) Network() string {
	return "bad"
}

func TestGetIPInfoFromIPIPInfoDisabledReturnsEmptyIPInfo(t *testing.T) {
	var emptyInfo IPInfo

	info, err := GetIPInfoFromIP(nil, net.IPv4(127, 0, 0, 1))

	require.Equal(t, emptyInfo, info)
	require.NoError(t, err)
}

func TestGetIPInfoFromIPNilAddressReturnsError(t *testing.T) {
	info, err := GetIPInfoFromIP(&noopMap{}, nil)

	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)
}

func TestGetIPInfoFromIPLocalhostAddressReturnsLocalLocation(t *testing.T) {
	info, err := GetIPInfoFromIP(&noopMap{}, net.IPv4(127, 0, 0, 1))

	require.NoError(t, err)
	require.Equal(t, localLocation, info.CountryCode)
}

func TestGetIPInfoFromIPLocalNetworkAddressReturnsUnknownLocation(t *testing.T) {
	info, err := GetIPInfoFromIP(&noopMap{}, net.IPv4(10, 0, 0, 1))

	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)
}

func TestGetIPInfoFromIPNoCountryFoundReturnsUnknownLocation(t *testing.T) {
	info, err := GetIPInfoFromIP(&noopMap{}, net.IPv4(8, 8, 8, 8))

	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)
}

func TestGetIPInfoFromIPFailedDBLookupReturnsError(t *testing.T) {
	info, err := GetIPInfoFromIP(&badMap{}, net.IPv4(8, 8, 8, 8))

	require.Error(t, err)
	require.Equal(t, errDbLookupError, info.CountryCode)
}

func TestGetIPInfoFromAddrIPInfoDisabledReturnsEmptyIPInfo(t *testing.T) {
	var emptyInfo IPInfo

	info, err := GetIPInfoFromAddr(nil, &badAddr{"127.0.0.1:port"})

	require.Equal(t, emptyInfo, info)
	require.NoError(t, err)
}

func TestGetIPInfoFromAddrNilAddressReturnsError(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, nil)

	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)
}

func TestGetIPInfoFromAddrHostNoPortReturnsError(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, &badAddr{"host-no-port"})

	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)
}

func TestGetIPInfoFromAddrHostIsNotIPReturnsError(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, &badAddr{"host-is-not-ip:port"})

	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)
}

func TestGetIPInfoFromAddrLocalhostAddressReturnsLocalLocation(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, &badAddr{"127.0.0.1:port"})

	require.NoError(t, err)
	require.Equal(t, localLocation, info.CountryCode)
}

func TestGetIPInfoFromAddrLocalNetworkAddressReturnsUnknownLocation(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, &badAddr{"10.0.0.1:port"})

	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)
}

func TestGetIPInfoFromAddrNoCountryFoundReturnsUnknownLocation(t *testing.T) {
	info, err := GetIPInfoFromAddr(&noopMap{}, &badAddr{"8.8.8.8:port"})

	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)
}

func TestGetIPInfoFromAddrFailedDBLookupReturnsError(t *testing.T) {
	info, err := GetIPInfoFromAddr(&badMap{}, &badAddr{"8.8.8.8:port"})

	require.Error(t, err)
	require.Equal(t, errDbLookupError, info.CountryCode)
}

func TestCountryCode(t *testing.T) {
	require.Equal(t, "BR", CountryCode("BR").String())
}

func BenchmarkGetIPInfoFromAddr(b *testing.B) {
	ip2info := &noopMap{}
	testAddr := &net.TCPAddr{IP: net.ParseIP("217.65.48.1"), Port: 12345}

	b.ResetTimer()
	// Repeatedly check the country for the same address.  This is realistic, because
	// servers call this method for each new connection, but typically many connections
	// come from a single user in succession.
	for i := 0; i < b.N; i++ {
		GetIPInfoFromAddr(ip2info, testAddr)
	}
}
