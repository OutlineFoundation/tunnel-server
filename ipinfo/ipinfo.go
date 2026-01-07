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
	"errors"
	"fmt"
	"net"
)

type IPInfoMap interface {
	GetIPInfo(net.IP) (IPInfo, error)
}

type IPInfo struct {
	CountryCode CountryCode
	ASN         ASN
}

type CountryCode string

func (cc CountryCode) String() string {
	return string(cc)
}

type ASN struct {
	Number       int
	Organization string
}

const (
	// Codes in the X* range are reserved to be user-assigned.
	// See https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2#Decoding_table
	errParseAddr     CountryCode = "XA"
	localLocation    CountryCode = "XL"
	errDbLookupError CountryCode = "XD"
	// Code "ZZ" is also used by Unicode as unknown country.
	unknownLocation CountryCode = "ZZ"
)

// GetIPInfoFromIP is a helper function to call [IPInfoMap].GetIPInfo using a [net.IP].
// It uses special country codes to indicate errors:
//   - "XL": IP is not global ("L" is for "Local").
//   - "XD": database error looking up the country code ("D" is for "DB").
//   - "ZZ": lookup returned an empty country code (same as the Unicode unknown location).
func GetIPInfoFromIP(ip2info IPInfoMap, ip net.IP) (IPInfo, error) {
	var info IPInfo
	if ip2info == nil {
		// Location is disabled. return empty info.
		return info, nil
	}

	if ip == nil {
		info.CountryCode = errParseAddr
		return info, errors.New("IP cannot be nil")
	}

	if !ip.IsGlobalUnicast() {
		info.CountryCode = localLocation
		return info, nil
	}
	info, err := ip2info.GetIPInfo(ip)
	if err != nil {
		info.CountryCode = errDbLookupError
	}
	if info.CountryCode == "" {
		info.CountryCode = unknownLocation
	}
	return info, err
}

// GetIPInfoFromAddr is a helper function to extract the IP address from the [net.Addr]
// and call [IPInfoMap].GetIPInfo.
// It uses special country codes to indicate errors:
//   - "XA": failed to extract the IP from the address ("A" is for "Address").
//   - "XL": IP is not global ("L" is for "Local").
//   - "XD": database error looking up the country code ("D" is for "DB").
//   - "ZZ": lookup returned an empty country code (same as the Unicode unknown location).
func GetIPInfoFromAddr(ip2info IPInfoMap, addr net.Addr) (IPInfo, error) {
	var info IPInfo
	if addr == nil {
		info.CountryCode = errParseAddr
		return info, errors.New("address cannot be nil")
	}
	hostname, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		info.CountryCode = errParseAddr
		return info, fmt.Errorf("failed to split hostname and port: %w", err)
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		info.CountryCode = errParseAddr
		return info, errors.New("failed to parse address as IP")
	}

	return GetIPInfoFromIP(ip2info, ip)
}
