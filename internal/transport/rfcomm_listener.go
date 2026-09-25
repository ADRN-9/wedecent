package transport

import (
	"errors"
	"net"
	"strconv"
)

// ListenRFCOMM creates a Bluetooth Classic RFCOMM stream listener on an
// explicit channel. Channel selection/discovery remains outside the transport;
// callers must configure a canonical channel from 1 through 30.
func ListenRFCOMM(channel int) (net.Listener, error) {
	if channel < 1 || channel > 30 {
		return nil, errors.New("transport: RFCOMM listen channel must be between 1 and 30")
	}
	return listenRFCOMM(uint8(channel))
}

func canonicalRFCOMMAddress(addr [6]uint8, channel uint8) string {
	// Linux sockaddr_rc stores bdaddr little-endian.
	return formatRFCOMMMAC([6]uint8{
		addr[5], addr[4], addr[3], addr[2], addr[1], addr[0],
	}) + "/" + strconv.Itoa(int(channel))
}

func formatRFCOMMMAC(addr [6]uint8) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 17)
	for i, value := range addr {
		base := i * 3
		out[base] = hex[value>>4]
		out[base+1] = hex[value&0x0f]
		if i != len(addr)-1 {
			out[base+2] = ':'
		}
	}
	return string(out)
}
