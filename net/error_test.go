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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConnectionErrorUnwrapCause(t *testing.T) {
	cause := errors.New("cause")
	err := &ConnectionError{Cause: cause}
	require.Equal(t, cause, err.Unwrap())
	require.ErrorIs(t, err, cause)
}

func TestConnectionErrorString(t *testing.T) {
	require.Equal(t, "example message", (&ConnectionError{Message: "example message"}).Error())
	require.Equal(t, "example message [ERR_EXAMPLE]", (&ConnectionError{Message: "example message", Status: "ERR_EXAMPLE"}).Error())

	cause := errors.New("cause")
	err := &ConnectionError{Status: "ERR_EXAMPLE", Message: "example message", Cause: cause}
	require.Equal(t, "example message [ERR_EXAMPLE]: cause", err.Error())
}

func TestConnectionErrorFromUnwrap(t *testing.T) {
	connErr := &ConnectionError{Message: "connection error"}
	topErr := fmt.Errorf("top error: %w", connErr)
	require.NotEqual(t, topErr, connErr)
	require.ErrorIs(t, topErr, connErr)
	var unwrapped *ConnectionError
	require.True(t, errors.As(topErr, &unwrapped))
	require.Equal(t, connErr, unwrapped)
}
