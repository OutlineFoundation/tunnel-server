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

	"github.com/oschwald/geoip2-golang"
)

// MMDBIpInfoMap is an [ipinfo.IPInfoMap] that uses MMDB files to lookup IP information.
type MMDBIPInfoMap struct {
	countryDB *geoip2.Reader
	asnDB     *geoip2.Reader
}

var _ IPInfoMap = (*MMDBIPInfoMap)(nil)

// NewMMDBIPInfoMap creates an [ipinfo.IPInfoMap] that uses the MMDB at countryDBPath to lookup IP Country information
// and the MMDB at asnDBPath to lookup IP ASN information. Either may be "", in which case you won't get the corresponding
// information in the IPInfo.
func NewMMDBIPInfoMap(countryDBPath string, asnDBPath string) (*MMDBIPInfoMap, error) {
	var ip2info MMDBIPInfoMap
	var countryErr, asnErr error
	if countryDBPath != "" {
		ip2info.countryDB, countryErr = geoip2.Open(countryDBPath)
	}
	if asnDBPath != "" {
		ip2info.asnDB, asnErr = geoip2.Open(asnDBPath)
	}
	return &ip2info, errors.Join(countryErr, asnErr)
}

func (ip2info *MMDBIPInfoMap) Close() error {
	var countryErr, asnErr error
	if ip2info.countryDB != nil {
		countryErr = ip2info.countryDB.Close()
	}
	if ip2info.asnDB != nil {
		asnErr = ip2info.asnDB.Close()
	}
	return errors.Join(countryErr, asnErr)
}

// GetIPInfo implements [IPInfoMap].GetIPInfo.
func (ip2info *MMDBIPInfoMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	var countryErr, asnErr error
	var info IPInfo
	if ip2info == nil {
		// Location is disabled. return empty info.
		return info, nil
	}
	if ip2info.countryDB != nil {
		var record *geoip2.Country
		record, countryErr = ip2info.countryDB.Country(ip)
		if countryErr != nil {
			countryErr = fmt.Errorf("country lookup failed: %w", countryErr)
		} else if record != nil && record.Country.IsoCode != "" {
			info.CountryCode = CountryCode(record.Country.IsoCode)
		}
	}
	if ip2info.asnDB != nil {
		var record *geoip2.ASN
		record, asnErr = ip2info.asnDB.ASN(ip)
		if asnErr != nil {
			asnErr = fmt.Errorf("asn lookup failed: %w", asnErr)
		} else if record != nil {
			info.ASN = ASN{
				Number:       int(record.AutonomousSystemNumber),
				Organization: record.AutonomousSystemOrganization,
			}
		}
	}
	return info, errors.Join(countryErr, asnErr)
}
