// Package speedtest implements a modified private speedtest protocol invited by Hysteria2.
package speedtest

import (
	"encoding/binary"
	"io"
	"strconv"
	"time"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	MagicAddress       = "@SpeedTest"        // Hysteria 2 use it.
	CustomMagicAddress = "speedtest.example" // Custom protocol hard fork. To make domain valid.

	TypeDownload = 0x01
	TypeUpload   = 0x02

	chunkSize = 64 * 1024
)

var (
	MagicSocksAddr       = M.Socksaddr{Fqdn: MagicAddress}
	CustomMagicSocksAddr = M.Socksaddr{Fqdn: CustomMagicAddress}
)

type Status byte

const (
	StatusOk    Status = 0x00
	StatusError Status = 0x01
)

func (s Status) String() string {
	switch s {
	case StatusOk:
		return "OK"
	case StatusError:
		return "Disallow"
	default:
		return strconv.Itoa(int(s))
	}
}

// DownloadRequest format:
// 0x1 (byte)
// Request data length (uint32 BE)

func readDownloadRequest(reader io.Reader) (length uint32, err error) {
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		err = E.Cause(err, "read download request")
	}
	return
}

func writeDownloadRequest(writer io.Writer, length uint32) (err error) {
	buffer := make([]byte, 5)
	buffer[0] = TypeDownload
	binary.BigEndian.PutUint32(buffer[1:], length)
	_, err = writer.Write(buffer)
	if err != nil {
		err = E.Cause(err, "write download request")
	}
	return
}

// DownloadResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (uint16 BE)
// Message (bytes)

func readDownloadResponse(reader io.Reader) (bool, []byte, error) {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil {
		return false, nil, E.Cause(err, "read download response status")
	}
	var messageLength uint16
	if err := binary.Read(reader, binary.BigEndian, &messageLength); err != nil {
		return false, nil, E.Cause(err, "read download response message length")
	}
	// No message is fine
	if messageLength == 0 {
		return Status(status[0]) == StatusOk, []byte{}, nil
	}
	buffer := buf.NewSize(int(messageLength))
	defer buffer.Release()
	_, err := buffer.ReadOnceFrom(reader)
	if err != nil {
		return false, nil, E.Cause(err, "read download response message (length: ", messageLength, ")")
	}
	return Status(status[0]) == StatusOk, buffer.Bytes(), nil
}

func writeDownloadResponse(writer io.Writer, ok bool, message []byte) (err error) {
	size := 1 + 2 + len(message)
	buffer := buf.NewSize(size)
	defer buffer.Release()
	if ok {
		common.Must(buffer.WriteByte(byte(StatusOk)))
	} else {
		common.Must(buffer.WriteByte(byte(StatusError)))
	}
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(len(message))))
	common.Must1(buffer.Write(message))
	_, err = writer.Write(buffer.Bytes())
	if err != nil {
		err = E.Cause(err, "write download response")
	}
	return
}

// UploadRequest format:
// 0x2 (byte)
// Upload data length (uint32 BE)

func readUploadRequest(reader io.Reader) (length uint32, err error) {
	err = binary.Read(reader, binary.BigEndian, &length)
	if err != nil {
		err = E.Cause(err, "read upload request")
	}
	return
}

func writeUploadRequest(writer io.Writer, l uint32) (err error) {
	buffer := make([]byte, 5)
	buffer[0] = TypeUpload
	binary.BigEndian.PutUint32(buffer[1:], l)
	_, err = writer.Write(buffer)
	if err != nil {
		err = E.Cause(err, "write upload request")
	}
	return
}

// UploadResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (uint16 BE)
// Message (bytes)

func readUploadResponse(reader io.Reader) (bool, []byte, error) {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil {
		return false, nil, E.Cause(err, "read upload response status")
	}
	var messageLength uint16
	if err := binary.Read(reader, binary.BigEndian, &messageLength); err != nil {
		return false, nil, E.Cause(err, "read upload response message length")
	}
	// No message is fine
	if messageLength == 0 {
		return Status(status[0]) == StatusOk, []byte{}, nil
	}
	buffer := buf.NewSize(int(messageLength))
	defer buffer.Release()
	_, err := buffer.ReadOnceFrom(reader)
	if err != nil {
		return false, nil, E.Cause(err, "read upload response message (length: ", messageLength, ")")
	}
	return Status(status[0]) == StatusOk, buffer.Bytes(), nil
}

func writeUploadResponse(writer io.Writer, ok bool, message []byte) (err error) {
	size := 1 + 2 + len(message)
	buffer := buf.NewSize(size)
	defer buffer.Release()
	if ok {
		common.Must(buffer.WriteByte(byte(StatusOk)))
	} else {
		common.Must(buffer.WriteByte(byte(StatusError)))
	}
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(len(message))))
	common.Must1(buffer.Write(message))
	_, err = writer.Write(buffer.Bytes())
	if err != nil {
		err = E.Cause(err, "write upload response")
	}
	return
}

// UploadSummary format:
// Duration (in milliseconds, uint32 BE)
// Received data length (uint32 BE)

func readUploadSummary(reader io.Reader) (time.Duration, uint32, error) {
	var duration uint32
	if err := binary.Read(reader, binary.BigEndian, &duration); err != nil {
		return 0, 0, E.Cause(err, "read upload duration")
	}
	var length uint32
	if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
		return 0, 0, E.Cause(err, "read upload summary length")
	}
	return time.Duration(duration) * time.Millisecond, length, nil
}

func writeUploadSummary(writer io.Writer, duration time.Duration, l uint32) (err error) {
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint32(buffer, uint32(duration/time.Millisecond))
	binary.BigEndian.PutUint32(buffer[4:], l)
	_, err = writer.Write(buffer)
	if err != nil {
		err = E.Cause(err, "write upload summary")
	}
	return
}
