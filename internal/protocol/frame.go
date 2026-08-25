package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	Version        = 1
	HeaderSize     = 12
	MaxPayloadSize = 1 << 20 // 1 MiB hard cap per frame.
)

var magic = [2]byte{'W', 'D'}

type Type uint8

const (
	TypePairRequest Type = 1 + iota
	TypePairResponse
	TypeOpenSession
	TypeSessionAccepted
	TypeData
	TypeResize
	TypeClose
	TypeError
	TypePing
	TypePong
)

type Frame struct {
	Type     Type
	StreamID uint32
	Payload  []byte
}

func WriteFrame(w io.Writer, f Frame) error {
	if len(f.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d", len(f.Payload))
	}
	header := make([]byte, HeaderSize)
	copy(header[:2], magic[:])
	header[2] = Version
	header[3] = byte(f.Type)
	binary.BigEndian.PutUint32(header[4:8], f.StreamID)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(f.Payload)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	return writeAll(w, f.Payload)
}

func ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	if header[0] != magic[0] || header[1] != magic[1] {
		return Frame{}, errors.New("invalid protocol magic")
	}
	if header[2] != Version {
		return Frame{}, fmt.Errorf("unsupported protocol version: %d", header[2])
	}
	length := binary.BigEndian.Uint32(header[8:12])
	if length > MaxPayloadSize {
		return Frame{}, fmt.Errorf("payload exceeds limit: %d", length)
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Type:     Type(header[3]),
		StreamID: binary.BigEndian.Uint32(header[4:8]),
		Payload:  payload,
	}, nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
