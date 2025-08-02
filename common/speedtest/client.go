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
		var copied uint32
		starts := timeFunc()
		lastUpdate := starts
		readCounter := func(n int64) {
			now := timeFunc()
			copied += uint32(n)
			callback(now.Sub(lastUpdate), uint32(n), false)
			lastUpdate = now
		}
		_, err = bufio.CopyWithCounters(
			io.Discard,
			&limitedReader{ExtendedReader: bufio.NewExtendedReader(conn), remaining: int(length)},
			conn,
			[]N.CountFunc{readCounter},
			nil,
			bufio.DefaultIncreaseBufferAfter,
			bufio.DefaultBatchSize,
		)
		if err != nil {
			done <- E.Cause(err, "copy download")
			return
		}
		callback(timeFunc().Sub(starts), copied, true)
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if ctxErr := ctx.Err(); ctxErr != nil && E.IsClosedOrCanceled(err) {
			return ctxErr
		}
		return err
	}
}

type limitedReader struct {
	N.ExtendedReader
	remaining int
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ExtendedReader.Read(p)
	r.remaining -= n
	return n, err
}

func (r *limitedReader) ReadBuffer(buffer *buf.Buffer) error {
	if r.remaining <= 0 {
		return io.EOF
	}
	if buffer.FreeLen() <= r.remaining {
		err := r.ExtendedReader.ReadBuffer(buffer)
		r.remaining -= buffer.Len()
		return err
	}

	n, err := r.ExtendedReader.Read(buffer.FreeBytes()[:r.remaining])
	buffer.Truncate(n)
	r.remaining -= n
	if n > 0 && err == io.EOF {
		return nil
	}
	return err
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
		wrapErr := func(err error) error {
			if err == nil {
				return nil
			}
			if ctxErr := ctx.Err(); ctxErr != nil && E.IsClosedOrCanceled(err) {
				return ctxErr
			}
			return err
		}
		writeChunk := func(p []byte) error {
			for len(p) > 0 {
				n, err := conn.Write(p)
				if n > 0 {
					writeCounter(int64(n))
					p = p[n:]
				}
				if err != nil {
					return wrapErr(err)
				}
			}
			return nil
		}

		if length <= chunkSize {
			data := randData(int(length))
			defer buf.Put(data)
			err := writeChunk(data)
			if err != nil {
				done <- E.Cause(err, "copy upload")
				return
			}
			duration, totalReceived, err := readUploadSummary(conn)
			if err != nil {
				done <- E.Cause(wrapErr(err), "read upload summary")
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

			err := writeChunk(chunk[:n])
			if err != nil {
				done <- E.Cause(err, "copy upload")
				return
			}
			remaining -= n
		}

		duration, totalReceived, err := readUploadSummary(conn)
		if err != nil {
			done <- E.Cause(wrapErr(err), "read upload summary")
			return
		}
		callback(duration, totalReceived, true)

		done <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if ctxErr := ctx.Err(); ctxErr != nil && E.IsClosedOrCanceled(err) {
			return ctxErr
		}
		return err
	}
}
