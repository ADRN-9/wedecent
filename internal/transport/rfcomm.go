package transport

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const defaultRFCOMMDialTimeout = 10 * time.Second

// RFCOMMDialer opens an RFCOMM stream to an explicitly configured Bluetooth
// Classic device/channel. It does not perform discovery or pairing; TLS and
// WeDecent identity verification remain above this transport boundary.
type RFCOMMDialer struct {
	Timeout time.Duration
}

type rfcommLocator struct {
	addr      [6]uint8
	channel   uint8
	canonical string
}

var errRFCOMMUnsupported = errors.New("transport: RFCOMM is unsupported on this platform")

func (d RFCOMMDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	if ctx == nil {
		return nil, errors.New("transport: nil RFCOMM dial context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	locator, err := parseRFCOMMLocator(endpoint)
	if err != nil {
		return nil, err
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultRFCOMMDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return dialRFCOMM(dialCtx, locator)
}

// NormalizeRFCOMMLocator validates an explicit Bluetooth Classic RFCOMM
// endpoint and returns its canonical MAC/channel form. It performs no
// discovery, pairing, channel selection, or trust inference.
func NormalizeRFCOMMLocator(endpoint string) (string, error) {
	locator, err := parseRFCOMMLocator(endpoint)
	if err != nil {
		return "", err
	}
	return locator.canonical, nil
}

func parseRFCOMMLocator(endpoint string) (rfcommLocator, error) {
	var zero rfcommLocator
	parts := strings.Split(endpoint, "/")
	if len(parts) != 2 {
		return zero, errors.New("transport: RFCOMM endpoint must be MAC/channel")
	}
	macText, channelText := parts[0], parts[1]
	if len(macText) != 17 {
		return zero, errors.New("transport: RFCOMM MAC must use XX:XX:XX:XX:XX:XX")
	}
	var networkOrder [6]uint8
	for i := 0; i < 6; i++ {
		if i < 5 && macText[i*3+2] != ':' {
			return zero, errors.New("transport: RFCOMM MAC must use colon separators")
		}
		value, err := strconv.ParseUint(macText[i*3:i*3+2], 16, 8)
		if err != nil {
			return zero, errors.New("transport: RFCOMM MAC contains invalid hex")
		}
		networkOrder[i] = uint8(value)
	}
	channel, err := strconv.Atoi(channelText)
	if err != nil || channel < 1 || channel > 30 || strconv.Itoa(channel) != channelText {
		return zero, errors.New("transport: RFCOMM channel must be canonical decimal 1-30")
	}

	locator := rfcommLocator{channel: uint8(channel)}
	for i := 0; i < len(networkOrder); i++ {
		locator.addr[i] = networkOrder[len(networkOrder)-1-i]
	}
	locator.canonical = fmt.Sprintf(
		"%02X:%02X:%02X:%02X:%02X:%02X/%d",
		networkOrder[0], networkOrder[1], networkOrder[2],
		networkOrder[3], networkOrder[4], networkOrder[5], channel,
	)
	return locator, nil
}

type rfcommAddr string

func (a rfcommAddr) Network() string { return "bluetooth-rfcomm" }
func (a rfcommAddr) String() string  { return string(a) }

var _ Dialer = RFCOMMDialer{}
