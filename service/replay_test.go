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

package service

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const keyID = "the key"

var counter uint32 = 0

func makeSalts(n int) [][]byte {
	salts := make([][]byte, n)
	for i := 0; i < n; i++ {
		salts[i] = make([]byte, 4)
		binary.BigEndian.PutUint32(salts[i], counter)
		counter++
		if counter == 0 {
			panic("Salt counter overflow")
		}
	}
	return salts
}

func TestReplayCache_Active(t *testing.T) {
	salts := makeSalts(2)
	cache := NewReplayCache(10)
	if !cache.Add(keyID, salts[0]) {
		t.Error("First addition to a clean cache should succeed")
	}
	if cache.Add(keyID, salts[0]) {
		t.Error("Duplicate add should fail")
	}
	if !cache.Add(keyID, salts[1]) {
		t.Error("Addition of a new vector should succeed")
	}
	if cache.Add(keyID, salts[1]) {
		t.Error("Second duplicate add should fail")
	}
}

func TestReplayCache_Archive(t *testing.T) {
	salts0 := makeSalts(10)
	salts1 := makeSalts(10)
	cache := NewReplayCache(10)
	// Add vectors to the active set until it hits the limit
	// and spills into the archive.
	for _, s := range salts0 {
		if !cache.Add(keyID, s) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	for _, s := range salts0 {
		if cache.Add(keyID, s) {
			t.Error("Duplicate add should fail")
		}
	}

	// Repopulate the active set.
	for _, s := range salts1 {
		if !cache.Add(keyID, s) {
			t.Error("Addition of a new vector should succeed")
		}
	}

	// Both active and archive are full.  Adding another vector
	// should wipe the archive.
	lastStraw := makeSalts(1)[0]
	if !cache.Add(keyID, lastStraw) {
		t.Error("Addition of a new vector should succeed")
	}
	for _, s := range salts0 {
		if !cache.Add(keyID, s) {
			t.Error("First 10 vectors should have been forgotten")
		}
	}
}

func TestReplayCache_Resize(t *testing.T) {
	t.Run("Smaller resizes active and archive maps", func(t *testing.T) {
		salts := makeSalts(10)
		cache := NewReplayCache(5)
		for _, s := range salts {
			cache.Add(keyID, s)
		}

		err := cache.Resize(3)

		require.NoError(t, err)
		assert.Equal(t, cache.capacity, 3, "Expected capacity to be updated")

		// Adding a new salt should trigger a shrinking of the active map as it hits the new
		// capacity immediately.
		cache.Add(keyID, salts[0])
		assert.Len(t, cache.active, 1, "Expected active handshakes length to have shrunk")
		assert.Len(t, cache.archive, 5, "Expected archive handshakes length to not have shrunk")

		// Adding more new salts should eventually trigger a shrinking of the archive map as well,
		// when the shrunken active map gets moved to the archive.
		for _, s := range salts {
			cache.Add(keyID, s)
		}
		assert.Len(t, cache.archive, 3, "Expected archive handshakes length to have shrunk")
	})

	t.Run("Larger resizes active and archive maps", func(t *testing.T) {
		salts := makeSalts(10)
		cache := NewReplayCache(5)
		for _, s := range salts {
			cache.Add(keyID, s)
		}

		err := cache.Resize(10)

		require.NoError(t, err)
		assert.Equal(t, cache.capacity, 10, "Expected capacity to be updated")
		assert.Len(t, cache.active, 5, "Expected active handshakes length not to have changed")
		assert.Len(t, cache.archive, 5, "Expected archive handshakes length not to have changed")
	})

	t.Run("Still detect salts", func(t *testing.T) {
		salts := makeSalts(10)
		cache := NewReplayCache(5)
		for _, s := range salts {
			cache.Add(keyID, s)
		}

		cache.Resize(10)

		for _, s := range salts {
			if cache.Add(keyID, s) {
				t.Error("Should still be able to detect the salts after resizing")
			}
		}

		cache.Resize(3)

		for _, s := range salts {
			if cache.Add(keyID, s) {
				t.Error("Should still be able to detect the salts after resizing")
			}
		}
	})

	t.Run("Exceeding maximum capacity", func(t *testing.T) {
		cache := &ReplayCache{}

		err := cache.Resize(MaxCapacity + 1)

		require.Error(t, err)
	})
}

// Benchmark to determine the memory usage of ReplayCache.
// Note that NewReplayCache only allocates the active set,
// so the eventual memory usage will be roughly double.
func BenchmarkReplayCache_Creation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewReplayCache(MaxCapacity)
	}
}

func BenchmarkReplayCache_Max(b *testing.B) {
	salts := makeSalts(b.N)
	// Archive replacements will be infrequent.
	cache := NewReplayCache(MaxCapacity)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(keyID, salts[i])
	}
}

func BenchmarkReplayCache_Min(b *testing.B) {
	salts := makeSalts(b.N)
	// Every addition will archive the active set.
	cache := NewReplayCache(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Add(keyID, salts[i])
	}
}

func BenchmarkReplayCache_Parallel(b *testing.B) {
	c := make(chan []byte, b.N)
	for _, s := range makeSalts(b.N) {
		c <- s
	}
	close(c)
	// Exercise both expansion and archiving.
	cache := NewReplayCache(100)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			cache.Add(keyID, <-c)
		}
	})
}
