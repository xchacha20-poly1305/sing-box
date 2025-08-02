package speedtest

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

// SpeedCallback is the callback of speed test.
//
// When end is false:
// duration is the time since last send / receive.
// received is the new received bytes since last send / receive.
//
// When end is true:
// duration and received means the total data.
type SpeedCallback func(duration time.Duration, received uint32, end bool)

func DownloadTest(ctx context.Context, conn net.Conn, length uint32, callback SpeedCallback) error {
	defer conn.Close()

	err := writeDownloadRequest(conn, length)
	if err != nil {
		return E.Cause(err, "write download request")
	}
	permitted, message, err := readDownloadResponse(conn)
	if err != nil {
		return E.Cause(err, "read download response")
	}
	if !permitted {
		return E.New("download test is forbidden: ", string(message))
	}
	_ = buf.Put(message)

	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}

	done := make(chan error, 1)

	go func() {
		var copied int64
		starts := timeFunc()
		lastUpdate := starts
		readCounter := func(n int64) {
			now := timeFunc()
			copied += n
			callback(now.Sub(lastUpdate), uint32(n), copied >= int64(length))
			lastUpdate = now
		}
		_, err = bufio.CopyWithCounters(io.Discard, conn, conn, []N.CountFunc{readCounter}, nil, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
		if err != nil {
			done <- E.Cause(err, "copy download")
		}
		callback(timeFunc().Sub(starts), uint32(copied), true)
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}

func UploadTest(ctx context.Context, conn net.Conn, length uint32, callback SpeedCallback) error {
	defer conn.Close()

	err := writeUploadRequest(conn, length)
	if err != nil {
		return err
	}
	permitted, message, err := readUploadResponse(conn)
	if err != nil {
		return err
	}
	if !permitted {
		return E.New("upload test is forbidden: ", string(message))
	}
	_ = buf.Put(message)

	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}

	done := make(chan error, 1)

	go func() {
		lastUpdate := timeFunc()
		writeCounter := func(n int64) {
			now := timeFunc()
			callback(now.Sub(lastUpdate), uint32(n), false)
			lastUpdate = now
		}

		if length <= chunkSize {
			data := randData(int(length))
			chunk := buf.As(data)
			defer chunk.Release()
			_, err := bufio.CopyWithCounters(conn, chunk, chunk, nil, []N.CountFunc{writeCounter}, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
			if err != nil {
				done <- E.Cause(err, "copy upload")
			}
			duration, totalReceived, err := readUploadSummary(conn)
			if err != nil {
				done <- E.Cause(err, "read upload summary")
				return
			}
			callback(duration, totalReceived, true)
			done <- nil
			return
		}

		chunk := randData(chunkSize)
		defer buf.Put(chunk)
		// Reuse buffer
		remaining := length
		for remaining > 0 {
			select {
			case <-ctx.Done():
				done <- ctx.Err()
				return
			default:
			}

			n := remaining
			if n > chunkSize {
				n = chunkSize
			}

			reader := buf.As(chunk[:n])
			_, err := bufio.CopyWithCounters(conn, reader, reader, nil, []N.CountFunc{writeCounter}, bufio.DefaultIncreaseBufferAfter, bufio.DefaultBatchSize)
			if err != nil {
				done <- E.Cause(err, "copy upload")
				return
			}
			remaining -= n
		}

		duration, totalReceived, err := readUploadSummary(conn)
		if err != nil {
			done <- E.Cause(err, "read upload summary")
			return
		}
		callback(duration, totalReceived, true)

		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		return err
	}
}
