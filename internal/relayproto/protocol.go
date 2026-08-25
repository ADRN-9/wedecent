package relayproto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ALPN       = "wedecent-relay/1"
	MaxMessage = 16 << 10
)

const (
	TypeChallenge = "challenge"
	TypeRegister  = "register"
	TypeConnect   = "connect"
	TypeWaiting   = "waiting"
	TypeReady     = "ready"
	TypeError     = "error"
)

type Message struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge,omitempty"`
	DeviceID  string `json:"device_id,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
	Code      string `json:"code,omitempty"`
	Error     string `json:"error,omitempty"`
}

func Write(w io.Writer, msg Message) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	if len(data) > MaxMessage {
		return errors.New("relay control message too large")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, data)
}

func Read(r io.Reader) (Message, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > MaxMessage {
		return Message{}, fmt.Errorf("invalid relay message size: %d", n)
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return Message{}, err
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, err
	}
	return msg, nil
}

func RegistrationBytes(challenge, deviceID string) []byte {
	return []byte("wedecent-relay-register-v1\x00" + challenge + "\x00" + deviceID)
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
