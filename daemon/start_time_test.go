package daemon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStartTimeTrusted(t *testing.T) {
	var start startTime
	require.True(t, start.Get().IsZero())
	start.Mark()
	first := start.Get()
	require.False(t, first.IsZero())
	time.Sleep(5 * time.Millisecond)
	require.Equal(t, first, start.Get(), "trusted start time must never change")
	start.Reset()
	require.True(t, start.Get().IsZero())
}
