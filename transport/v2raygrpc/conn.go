package v2raygrpc

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ net.Conn = (*GRPCConn)(nil)

type GRPCConn struct {
	GunService
	cache     []byte
	cancel    context.CancelCauseFunc
	closeOnce sync.Once
}

func NewGRPCConn(service GunService, cancel context.CancelCauseFunc) *GRPCConn {
	//nolint:staticcheck
	if client, isClient := service.(GunService_TunClient); isClient {
		service = &clientConnWrapper{client}
	}
	return &GRPCConn{
		GunService: service,
		cancel:     cancel,
	}
}

func (c *GRPCConn) Read(b []byte) (n int, err error) {
	if len(c.cache) > 0 {
		n = copy(b, c.cache)
		c.cache = c.cache[n:]
		return
	}
	hunk, err := c.Recv()
	err = baderror.WrapGRPC(err)
	if err != nil {
		return
	}
	n = copy(b, hunk.Data)
	if n < len(hunk.Data) {
		c.cache = hunk.Data[n:]
	}
	return
}

func (c *GRPCConn) Write(b []byte) (n int, err error) {
	err = baderror.WrapGRPC(c.Send(&Hunk{Data: b}))
	if err != nil {
		return
	}
	return len(b), nil
}

func (c *GRPCConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel(nil)
		}
	})
	return nil
}

func (c *GRPCConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *GRPCConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *GRPCConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *GRPCConn) Upstream() any {
	return c.GunService
}

var _ N.WriteCloser = (*clientConnWrapper)(nil)

type clientConnWrapper struct {
	GunService_TunClient
}

func (c *clientConnWrapper) CloseWrite() error {
	return c.CloseSend()
}

var (
	_ net.Conn               = (*GRPCMultiConn)(nil)
	_ N.VectorisedWriter     = (*GRPCMultiConn)(nil)
	_ N.VectorisedReadWaiter = (*GRPCMultiConn)(nil)
)

type GRPCMultiConn struct {
	GunMultiService
	cache           bytes.Buffer
	readWaitOptions N.ReadWaitOptions
	cancel          context.CancelCauseFunc
	closeOnce       sync.Once
}

func NewGRPCMultiConn(service GunMultiService, cancel context.CancelCauseFunc) *GRPCMultiConn {
	if client, isClient := service.(GunService_TunMultiClient); isClient {
		service = &clientMultiConnWrapper{client}
	}
	return &GRPCMultiConn{
		GunMultiService: service,
		cancel:          cancel,
	}
}

func (c *GRPCMultiConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return false
}

func (c *GRPCMultiConn) WaitReadBuffers() (buffers []*buf.Buffer, err error) {
	if c.cache.Len() > 0 {
		buffer := c.readWaitOptions.NewBuffer()
		_, err = c.cache.WriteTo(buffer)
		if err != nil {
			return
		}
		buffers = append(buffers, buffer)
		return
	}
	multiHunk, err := c.Recv()
	err = baderror.WrapGRPC(err)
	if err != nil {
		return
	}
	buffers = common.Map(multiHunk.Data, func(it []byte) *buf.Buffer {
		return buf.As(it)
	})
	return
}

func (c *GRPCMultiConn) Read(b []byte) (n int, err error) {
	if c.cache.Len() > 0 {
		return c.cache.Read(b)
	}
	multiHunk, err := c.Recv()
	err = baderror.WrapGRPC(err)
	if err != nil {
		return
	}
	var overflow bool
	for _, data := range multiHunk.Data {
		if !overflow {
			copied := copy(b[n:], data)
			n += copied
			if copied == len(data) && copied > 0 {
				continue
			}
			overflow = true
			data = data[copied:]
		}
		_, _ = c.cache.Write(data)
	}
	return
}

func (c *GRPCMultiConn) WriteVectorised(buffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(buffers)
	return baderror.WrapGRPC(c.Send(&MultiHunk{
		Data: buf.ToSliceMulti(buffers),
	}))
}

func (c *GRPCMultiConn) Write(b []byte) (n int, err error) {
	err = baderror.WrapGRPC(c.Send(&MultiHunk{Data: [][]byte{b}}))
	if err != nil {
		return
	}
	return len(b), nil
}

func (c *GRPCMultiConn) Close() error {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel(nil)
		}
	})
	return nil
}

func (c *GRPCMultiConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *GRPCMultiConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *GRPCMultiConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCMultiConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCMultiConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *GRPCMultiConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *GRPCMultiConn) Upstream() any {
	return c.GunMultiService
}

var _ N.WriteCloser = (*clientMultiConnWrapper)(nil)

type clientMultiConnWrapper struct {
	GunService_TunMultiClient
}

func (c *clientMultiConnWrapper) CloseWrite() error {
	return c.CloseSend()
}
