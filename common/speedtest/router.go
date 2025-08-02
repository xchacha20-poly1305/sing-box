package speedtest

import (
	std_bufio "bufio"
	"context"
	"crypto/rand"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

var _ adapter.ConnectionRouterEx = (*Router)(nil)

type HandleOption uint8

const (
	HandleDisable = iota
	HandleReject
	HandleAllow
)

func ParseHandleOption(option string) HandleOption {
	switch option {
	case "reject":
		return HandleReject
	case "allow":
		return HandleAllow
	case "disable":
		fallthrough
	default:
		return HandleDisable
	}
}

type Router struct {
	router       adapter.ConnectionRouterEx
	logger       logger.ContextLogger
	handleOption HandleOption
}

func NewRouter(router adapter.ConnectionRouterEx, logger logger.ContextLogger, handleOption HandleOption) adapter.ConnectionRouterEx {
	switch handleOption {
	case HandleAllow, HandleReject:
	default:
		return router
	}
	return &Router{router, logger, handleOption}
}

func (r *Router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	switch metadata.Destination.Fqdn {
	case MagicAddress, CustomMagicAddress:
	default:
		return r.router.RouteConnection(ctx, conn, metadata)
	}
	err := r.speedTest(ctx, conn, metadata.Source)
	if err != nil {
		r.logger.WarnContext(ctx, "route speedtest: ", err)
	}
	_ = conn.Close()
	return nil
}

func (r *Router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return r.router.RoutePacketConnection(ctx, conn, metadata)
}

func (r *Router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	switch metadata.Destination.Fqdn {
	case MagicAddress, CustomMagicAddress:
	default:
		r.router.RouteConnectionEx(ctx, conn, metadata, onClose)
		return
	}
	err := r.speedTest(ctx, conn, metadata.Source)
	if err != nil {
		r.logger.ErrorContext(ctx, "route speedtest: ", err)
	}
	_ = conn.Close()
}

func (r *Router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.router.RoutePacketConnectionEx(ctx, conn, metadata, onClose)
}

func (r *Router) speedTest(ctx context.Context, conn net.Conn, source M.Socksaddr) (err error) {
	switch r.handleOption {
	case HandleDisable:
		return nil
	case HandleReject:
		fallthrough
	case HandleAllow:
		fallthrough
	default:
	}
	r.logger.InfoContext(ctx, "inbound speedtest connection from: ", source)
	var _type [1]byte
	_, err = io.ReadFull(conn, _type[:])
	if err != nil {
		return E.Cause(err, "read speedtest type")
	}
	switch _type[0] {
	case TypeDownload:
		err = r.downloadTest(ctx, conn)
	case TypeUpload:
		err = r.uploadTest(ctx, conn)
	default:
		err = E.New("unknown speedtest type: ", _type[0])
	}
	return
}

func (r *Router) downloadTest(ctx context.Context, conn net.Conn) error {
	if r.handleOption == HandleReject {
		err := writeDownloadResponse(conn, false, []byte(StatusError.String()))
		if err != nil {
			return E.Cause(err, "write reject download response")
		}
		return nil
	}
	length, err := readDownloadRequest(conn)
	if err != nil {
		return err
	}
	err = writeDownloadResponse(conn, true, []byte(StatusOk.String()))
	if err != nil {
		return E.Cause(err, "write download OK response")
	}
	if length <= chunkSize {
		data := randData(int(length))
		defer buf.Put(data)
		_, err := conn.Write(data)
		if err != nil {
			return E.Cause(err, "write download data")
		}
		return nil
	}

	chunk := randData(chunkSize)
	defer buf.Put(chunk)
	// Reuse buffer
	remaining := length
	for remaining > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n := remaining
		if n > chunkSize {
			n = chunkSize
		}
		_, err := conn.Write(chunk[:n])
		if err != nil {
			return E.Cause(err, "write download data")
		}
		remaining -= n
	}
	return nil
}

func (r *Router) uploadTest(ctx context.Context, conn net.Conn) error {
	if r.handleOption == HandleReject {
		err := writeUploadResponse(conn, false, []byte(StatusError.String()))
		if err != nil {
			return E.Cause(err, "write reject upload response")
		}
		return nil
	}
	length, err := readUploadRequest(conn)
	if err != nil {
		return err
	}
	err = writeUploadResponse(conn, true, []byte(StatusOk.String()))
	if err != nil {
		return E.Cause(err, "write upload OK response")
	}
	timeFunc := ntp.TimeFuncFromContext(ctx)
	if timeFunc == nil {
		timeFunc = time.Now
	}
	start := timeFunc()
	_, err = bufio.Copy(&limitedDiscard{ctx: ctx, limit: uint64(length)}, conn)
	if err != nil {
		return err
	}
	return writeUploadSummary(conn, timeFunc().Sub(start), length)
}

func (r *Router) Upstream() any {
	return r.router
}

func randData(size int) []byte {
	buffer := buf.Get(size)
	_, _ = rand.Read(buffer)
	return buffer
}

type limitedDiscard struct {
	ctx     context.Context
	limit   uint64
	written uint64
}

func (l *limitedDiscard) Write(p []byte) (n int, err error) {
	select {
	case <-l.ctx.Done():
		return 0, l.ctx.Err()
	default:
	}
	if l.written >= l.limit {
		return 0, std_bufio.ErrBufferFull
	}

	// Prevent overflowing
	remaining := l.limit - l.written
	toWrite := len(p)
	if uint64(toWrite) > remaining {
		toWrite = int(remaining)
	}
	if toWrite == 0 && len(p) > 0 {
		return 0, std_bufio.ErrBufferFull
	}
	l.written += uint64(toWrite)

	return toWrite, nil
}
