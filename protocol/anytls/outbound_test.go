package anytls

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdated(t *testing.T) {
	require.NotPanics(t, func() { (&Outbound{}).InterfaceUpdated(context.Background()) })
}

func TestMultiplexEnabled(t *testing.T) {
	require.True(t, (&Outbound{}).MultiplexEnabled())
	require.False(t, (&Outbound{disableReuse: true}).MultiplexEnabled())
}
