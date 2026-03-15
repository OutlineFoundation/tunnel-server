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

package ipinfo

import (
	"io/fs"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTestDataExists(t *testing.T) {
	_, err := os.Stat("../third_party/maxmind/test-data")
	// The test data is in a git submodule that must be initialized before running the test.
	require.NotErrorIs(t, err, fs.ErrNotExist, "Test MMDB directory not found. Make sure you ran `git submodule update --init --depth=1`")
}

func TestIPInfoMapNil(t *testing.T) {
	var infoMap *MMDBIPInfoMap = nil
	info, err := infoMap.GetIPInfo(net.ParseIP("111.235.160.0"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)
}

func TestIPInfoMapEmpty(t *testing.T) {
	ip2info, err := NewMMDBIPInfoMap("", "")
	require.NoError(t, err)
	defer ip2info.Close()

	info, err := ip2info.GetIPInfo(net.ParseIP("111.235.160.0"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)
}

func TestIPInfoMapCountryOnly(t *testing.T) {
	ip2info, err := NewMMDBIPInfoMap("../third_party/maxmind/test-data/GeoLite2-Country-Test.mmdb", "")
	require.NoError(t, err)
	defer ip2info.Close()

	// For examples, see https://github.com/maxmind/MaxMind-DB/blob/main/source-data/GeoLite2-Country-Test.json
	info, err := ip2info.GetIPInfo(net.ParseIP("111.235.160.0"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{CountryCode: "CN"}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("2a02:d280::"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{CountryCode: "CZ"}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("::1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)
}

func TestIPInfoMapASNOnly(t *testing.T) {
	ip2info, err := NewMMDBIPInfoMap("", "../third_party/maxmind/test-data/GeoLite2-ASN-Test.mmdb")
	require.NoError(t, err)
	defer ip2info.Close()

	// For examples, see https://github.com/maxmind/MaxMind-DB/blob/main/source-data/GeoLite2-ASN-Test.json
	info, err := ip2info.GetIPInfo(net.ParseIP("38.108.80.24"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{ASN: ASN{Number: 174, Organization: "Cogent Communications"}}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("2400::1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{ASN: ASN{Number: 4766, Organization: "Korea Telecom"}}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("::1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)
}

func TestIPInfoMap(t *testing.T) {
	ip2info, err := NewMMDBIPInfoMap("../third_party/maxmind/test-data/GeoLite2-Country-Test.mmdb", "../third_party/maxmind/test-data/GeoLite2-ASN-Test.mmdb")
	require.NoError(t, err)
	defer ip2info.Close()

	info, err := ip2info.GetIPInfo(net.ParseIP("67.43.156.0"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{CountryCode: "BT", ASN: ASN{Number: 35908, Organization: ""}}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("2a02:d280::"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{CountryCode: "CZ"}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("2400::1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{ASN: ASN{Number: 4766, Organization: "Korea Telecom"}}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("10.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("127.0.0.1"))
	require.NoError(t, err)
	assert.Equal(t, IPInfo{}, info)
}

func BenchmarkNewMMDBIPInfoMap(b *testing.B) {
	ip2info, err := NewMMDBIPInfoMap("../third_party/maxmind/test-data/GeoLite2-Country-Test.mmdb", "../third_party/maxmind/test-data/GeoLite2-ASN-Test.mmdb")
	require.NoError(b, err)
	defer ip2info.Close()

	testIP := net.ParseIP("217.65.48.1")
	b.ResetTimer()
	// Repeatedly check the country for the same address.  This is realistic, because
	// servers call this method for each new connection, but typically many connections
	// come from a single user in succession.
	for i := 0; i < b.N; i++ {
		ip2info.GetIPInfo(testIP)
	}
}
