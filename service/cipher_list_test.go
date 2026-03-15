// Copyright 2018 The Outline Authors
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

package service

import (
	"math/rand"
	"net/netip"
	"testing"
)

func BenchmarkLocking(b *testing.B) {
	var ip netip.Addr

	ciphers, _ := MakeTestCiphers([]string{"secret"})
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			entries := ciphers.SnapshotForClientIP(netip.Addr{})
			ciphers.MarkUsedByClientIP(entries[0], ip)
		}
	})
}

func BenchmarkSnapshot(b *testing.B) {
	// Create a list of cipher entries in a random order.

	// Small cipher lists (N~1e3) fit entirely in cache, and are ~10 times
	// faster to copy (per entry) than very large cipher lists (N~1e5).
	const N = 1e3
	ciphers, _ := MakeTestCiphers(makeTestSecrets(N))

	// Shuffling simulates the behavior of a real server, where successive
	// ciphers are not expected to be nearby in memory.
	entries := ciphers.SnapshotForClientIP(netip.Addr{})
	rand.Shuffle(N, func(i, j int) {
		entries[i], entries[j] = entries[j], entries[i]
	})
	for _, entry := range entries {
		// Reorder the list to match the shuffle
		// (actually in reverse, but it doesn't matter).
		ciphers.MarkUsedByClientIP(entry, netip.Addr{})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ciphers.SnapshotForClientIP(netip.Addr{})
		}
	})
}
