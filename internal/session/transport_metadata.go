package session

import "errors"

type TransportKind string

const (
	TransportDirectTCP       TransportKind = "direct_tcp"
	TransportBluetoothRFCOMM TransportKind = "bluetooth_rfcomm"
	TransportUSBCDCACM       TransportKind = "usb_cdc_acm"
	TransportRelay           TransportKind = "relay"
)

type UnderlyingTransport string

const (
	UnderlyingUSBNCM UnderlyingTransport = "usb_ncm"
)

// TransportMetadata is supplied by the local listener or transport adapter.
// It is audit context only: it must never be used as identity, trust,
// authorization, or routing evidence.
type TransportMetadata struct {
	Kind       TransportKind
	Underlying UnderlyingTransport
}

func (m TransportMetadata) Validate() error {
	switch m.Kind {
	case TransportDirectTCP, TransportBluetoothRFCOMM, TransportUSBCDCACM, TransportRelay:
	default:
		return errors.New("session: unsupported transport kind")
	}

	switch m.Underlying {
	case "":
		return nil
	case UnderlyingUSBNCM:
		if m.Kind != TransportDirectTCP {
			return errors.New("session: USB NCM can only underlay direct TCP")
		}
		return nil
	default:
		return errors.New("session: unsupported underlying transport")
	}
}

func (m TransportMetadata) auditLabel() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	if m.Underlying == "" {
		return string(m.Kind), nil
	}
	return string(m.Kind) + "+" + string(m.Underlying), nil
}
