//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"io"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"

	"golang.org/x/sys/unix"
)

func (i *Inbound) routeConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if i.tcpSpliceBackend != nil {
		ctx = service.ContextWith[adapter.ConnectionSplicer](ctx, i)
	}
	i.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func (i *Inbound) TrySpliceTCP(
	ctx context.Context,
	dialer N.Dialer,
	local net.Conn,
	remote net.Conn,
	metadata adapter.InboundContext,
	onClose N.CloseHandlerFunc,
) bool {
	backend := i.tcpSpliceBackend
	outbound, isOutbound := dialer.(adapter.Outbound)
	if backend == nil {
		return false
	}
	if !isOutbound || outbound.Type() != C.TypeDirect {
		backend.RecordFallback(ECommon.SpliceFallbackNotDirect)
		return false
	}
	if metadata.TLSFragment || metadata.TLSRecordFragment || metadata.TLSSpoof != "" {
		backend.RecordFallback(ECommon.SpliceFallbackTransformed)
		return false
	}
	if powerManager := service.FromContext[*powerreport.Manager](ctx); powerManager != nil && powerManager.Recorder() != nil {
		backend.RecordFallback(ECommon.SpliceFallbackPowerReportActive)
		return false
	}
	localTCP := spliceTCPConn(local)
	remoteTCP := spliceTCPConn(remote)
	if localTCP == nil || remoteTCP == nil {
		backend.RecordFallback(ECommon.SpliceFallbackNotPlainTCP)
		return false
	}
	if err := flushSpliceCachedData(local, remoteTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackCachedData)
		i.logger.DebugContext(ctx, "experimental eBPF TCP splice fallback while flushing cached data: ", err)
		return false
	}
	if err := drainSpliceReceiveQueue(localTCP, remoteTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackInboundQueue)
		i.logger.DebugContext(ctx, "experimental eBPF TCP splice fallback while draining inbound data: ", err)
		return false
	}
	if err := drainSpliceReceiveQueue(remoteTCP, localTCP); err != nil {
		backend.RecordFallback(ECommon.SpliceFallbackOutboundQueue)
		i.logger.DebugContext(ctx, "experimental eBPF TCP splice fallback while draining outbound data: ", err)
		return false
	}
	trafficCounter := spliceTrafficCounter(local)
	var account func(upload, download int64)
	if trafficCounter != nil {
		account = trafficCounter.CountKernelTraffic
	}
	pair, err := backend.BeginPair(localTCP, remoteTCP, onClose, account)
	if err != nil {
		i.logger.DebugContext(ctx, "experimental eBPF TCP splice fallback while publishing pair: ", err)
		return false
	}
	if err = pair.Activate(); err != nil {
		backend.Abort(pair)
		i.logger.DebugContext(ctx, "experimental eBPF TCP splice fallback while activating pair: ", err)
		return false
	}
	return true
}

func spliceTrafficCounter(conn net.Conn) adapter.KernelTrafficCounter {
	var counter adapter.KernelTrafficCounter
	_ = walkSpliceConn(conn, func(current net.Conn) bool {
		counter, _ = current.(adapter.KernelTrafficCounter)
		return counter != nil
	})
	return counter
}

const spliceConnChainLimit = 16

func walkSpliceConn(conn net.Conn, visit func(net.Conn) bool) bool {
	for depth := 0; conn != nil; depth++ {
		if depth >= spliceConnChainLimit {
			return false
		}
		if visit(conn) {
			return true
		}
		if _, isTCP := conn.(*net.TCPConn); !isTCP {
			reader, readerOK := conn.(interface{ ReaderReplaceable() bool })
			writer, writerOK := conn.(interface{ WriterReplaceable() bool })
			if !readerOK || !writerOK || !reader.ReaderReplaceable() || !writer.WriterReplaceable() {
				break
			}
		}
		if upstream, loaded := conn.(interface{ Upstream() any }); loaded {
			if next, nextLoaded := upstream.Upstream().(net.Conn); nextLoaded && next != nil && next != conn {
				conn = next
				continue
			}
		}
		if netConn, loaded := conn.(interface{ NetConn() net.Conn }); loaded {
			if next := netConn.NetConn(); next != nil && next != conn {
				conn = next
				continue
			}
		}
		break
	}
	return true
}

func spliceTCPConn(conn net.Conn) *net.TCPConn {
	var tcpConn *net.TCPConn
	opaque := false
	complete := walkSpliceConn(conn, func(current net.Conn) bool {
		if isOpaqueSpliceConn(current) {
			opaque = true
			return true
		}
		if tcp, loaded := current.(*net.TCPConn); loaded {
			tcpConn = tcp
			return true
		}
		return false
	})
	if !complete || opaque {
		return nil
	}
	return tcpConn
}

func isOpaqueSpliceConn(conn net.Conn) bool {
	name := strings.ToLower(reflect.TypeOf(conn).String())
	for _, marker := range []string{"tls.", "utls.", "tlsfragment.", "tlsspoof.", "shadowsocks.", "vmess.", "vless.", "trojan.", "shadowtls.", "anytls.", "hysteria.", "tuic.", "naive.", "reality.", "mux.", "smux.", "yamux."} {
		if strings.Contains(name, marker) {
			return true
		}
	}
	return false
}

func flushSpliceCachedData(local net.Conn, remote *net.TCPConn) error {
	var flushErr error
	complete := walkSpliceConn(local, func(current net.Conn) bool {
		cached, loaded := current.(N.CachedReader)
		if !loaded {
			return false
		}
		buffer := cached.ReadCached()
		if buffer == nil {
			return false
		}
		defer buffer.Release()
		if buffer.Len() == 0 {
			return false
		}
		_, flushErr = remote.Write(buffer.Bytes())
		return flushErr != nil
	})
	if flushErr != nil {
		return flushErr
	}
	if !complete {
		return E.New("TCP connection wrapper chain is too deep")
	}
	return nil
}

func drainSpliceReceiveQueue(source, destination *net.TCPConn) error {
	const maxRounds = 32
	var buffer *buf.Buffer
	defer func() {
		if buffer != nil {
			buffer.Release()
		}
	}()
	for range maxRounds {
		queued, err := spliceReceiveQueueSize(source)
		if err != nil || queued == 0 {
			return err
		}
		if queued > 64*1024 {
			queued = 64 * 1024
		}
		if buffer == nil || buffer.Cap() < queued {
			if buffer != nil {
				buffer.Release()
			}
			buffer = buf.NewSize(queued)
		}
		payload := buffer.FreeBytes()[:queued]
		_ = source.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		read, readErr := source.Read(payload)
		_ = source.SetReadDeadline(time.Time{})
		if read > 0 {
			if _, err = destination.Write(payload[:read]); err != nil {
				return err
			}
		}
		if readErr != nil {
			if timeout, loaded := readErr.(net.Error); loaded && timeout.Timeout() && read > 0 {
				continue
			}
			if readErr == io.EOF && read > 0 {
				return nil
			}
			return readErr
		}
	}
	queued, err := spliceReceiveQueueSize(source)
	if err != nil {
		return err
	}
	if queued != 0 {
		return E.New("TCP receive queue remained busy")
	}
	return nil
}

func spliceReceiveQueueSize(conn *net.TCPConn) (int, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var queued int
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		queued, controlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
	})
	if err != nil {
		return 0, err
	}
	return queued, controlErr
}

var _ adapter.ConnectionSplicer = (*Inbound)(nil)
