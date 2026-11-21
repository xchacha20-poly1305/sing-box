package doh

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/miekg/dns"
)

const mediaType = "application/dns-message"

func ResolvePath(value string) (string, error) {
	if value == "" {
		return "/dns-query", nil
	}
	if !strings.HasPrefix(value, "/") || value == "/" || path.Clean(value) != value ||
		strings.ContainsAny(value, "{}*") || (&url.URL{Path: value}).EscapedPath() != value {
		return "", E.New("invalid doh.path: ", value)
	}
	return value, nil
}

func CheckPathConflict(value string, subtree string) error {
	if value == subtree || strings.HasPrefix(value, subtree+"/") {
		return E.New("doh.path ", value, " conflicts with ", subtree)
	}
	return nil
}

type Handler struct {
	path        string
	router      adapter.DNSRouter
	inbound     string
	inboundType string
}

func NewHandler(router adapter.DNSRouter, path string, inbound string, inboundType string) *Handler {
	return &Handler{
		router:      router,
		path:        path,
		inbound:     inbound,
		inboundType: inboundType,
	}
}

func (h *Handler) Matches(request *http.Request) bool {
	return request.URL.EscapedPath() == h.path
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !h.Matches(request) {
		http.NotFound(writer, request)
		return
	}
	buffer, status := readQuery(writer, request)
	if status != http.StatusOK {
		http.Error(writer, http.StatusText(status), status)
		return
	}
	defer buffer.Release()
	wire := buffer.Bytes()
	var message dns.Msg
	if err := message.Unpack(wire); err != nil || message.Response || message.Opcode != dns.OpcodeQuery {
		http.Error(writer, "invalid DNS query", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(log.ContextWithNewID(request.Context()), C.DNSTimeout)
	defer cancel()
	user, _ := auth.UserFromContext[string](ctx)
	ctx = adapter.WithContext(ctx, &adapter.InboundContext{
		Inbound:     h.inbound,
		InboundType: h.inboundType,
		Source:      M.ParseSocksaddr(request.RemoteAddr).Unwrap(),
		Network:     N.NetworkTCP,
		User:        user,
	})
	id := message.Id
	response, err := h.router.Exchange(ctx, &message, adapter.DNSQueryOptions{})
	if E.IsTimeout(err) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		http.Error(writer, "DNS query timed out", http.StatusGatewayTimeout)
		return
	}
	if err != nil || response == nil {
		http.Error(writer, "DNS exchange failed", http.StatusBadGateway)
		return
	}
	reply := *response
	reply.Id = id
	reply.Compress = true
	wire, err = reply.Pack()
	if err != nil || len(wire) > dns.MaxMsgSize {
		http.Error(writer, "DNS response encoding failed", http.StatusBadGateway)
		return
	}
	writer.Header().Set("Content-Type", mediaType)
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write(wire)
}

// readQuery returns a not nil buffer when status is http.StatusOK and nil when not.
func readQuery(writer http.ResponseWriter, request *http.Request) (buffer *buf.Buffer, status int) {
	switch request.Method {
	case http.MethodGet:
		parameters, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil {
			return nil, http.StatusBadRequest
		}
		query := parameters["dns"]
		if len(query) != 1 || query[0] == "" || strings.ContainsAny(query[0], "\r\n") {
			return nil, http.StatusBadRequest
		}
		if len(query[0]) > base64.RawURLEncoding.EncodedLen(dns.MaxMsgSize) {
			return nil, http.StatusRequestEntityTooLarge
		}
		strict := base64.RawStdEncoding.Strict()
		size := strict.DecodedLen(len(query[0]))
		buffer = buf.NewSize(size)
		decoded, err := strict.Decode(buffer.FreeBytes(), []byte(query[0]))
		if err != nil {
			buffer.Release()
			return nil, http.StatusBadRequest
		}
		buffer.Extend(decoded)
		return buffer, http.StatusOK
	case http.MethodPost:
		contentType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || contentType != mediaType {
			return nil, http.StatusUnsupportedMediaType
		}
		if request.ContentLength > dns.MaxMsgSize {
			return nil, http.StatusRequestEntityTooLarge
		}
		const maxReadSize = dns.MaxMsgSize + 1
		const normalDNSSize = 512 // normal DNS request smaller than 512
		size := normalDNSSize
		if request.ContentLength >= 0 {
			size = int(request.ContentLength) + 1
		}
		// Leave room for one extra byte to distinguish a full DNS message from an oversized body.
		buffer = buf.NewSize(size)
		_, err = buffer.ReadFrom(request.Body)
		for errors.Is(err, io.ErrShortBuffer) && buffer.IsFull() && size < maxReadSize {
			size = min(size*2, maxReadSize)
			next := buf.NewSize(size)
			copy(next.Extend(buffer.Len()), buffer.Bytes())
			buffer.Release()
			buffer = next
			_, err = buffer.ReadFrom(request.Body)
		}
		if buffer.Len() > dns.MaxMsgSize {
			buffer.Release()
			return nil, http.StatusRequestEntityTooLarge
		}
		if err != nil {
			buffer.Release()
			return nil, http.StatusBadRequest
		}
		return buffer, http.StatusOK
	default:
		writer.Header().Set("Allow", "GET, POST")
		return nil, http.StatusMethodNotAllowed
	}
}
