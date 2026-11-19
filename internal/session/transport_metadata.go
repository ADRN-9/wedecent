package session

import (
	"errors"
	"net"
)

type TransportKind string

const (
	TransportDirectTCP       TransportKind = "direct_tcp"
	TransportBluetoothRFCOMM TransportKind = "bluetooth_rfcomm"
	TransportUSBCDCACM       TransportKind = "usb_cdc_acm"
	TransportRelay           TransportKind = "relay"
	TransportRouted          TransportKind = "routed"
)

type UnderlyingTransport string

const (
	UnderlyingUSBNCM   UnderlyingTransport = "usb_ncm"
	UnderlyingLAN      UnderlyingTransport = "lan"
	UnderlyingInternet UnderlyingTransport = "internet"
)

// TransportMetadata is supplied by the local listener or authenticated route
// ingress. It is audit context only; it never grants identity or authority.
type TransportMetadata struct {
	Kind          TransportKind
	Underlying    UnderlyingTransport
	RouteRouterID string
}

func (m TransportMetadata) Validate() error {
	switch m.Kind {
	case TransportDirectTCP, TransportBluetoothRFCOMM, TransportUSBCDCACM, TransportRelay, TransportRouted:
	default:
		return errors.New("session: unsupported transport kind")
	}

	if m.Kind == TransportRouted {
		if !validSessionDeviceID(m.RouteRouterID) {
			return errors.New("session: routed transport requires an authenticated router device ID")
		}
		if m.Underlying != UnderlyingLAN && m.Underlying != UnderlyingInternet {
			return errors.New("session: routed transport requires a LAN or internet underlay")
		}
		return nil
	}
	if m.RouteRouterID != "" {
		return errors.New("session: router identity is only valid for routed transport")
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
	if m.Kind == TransportRouted {
		return string(m.Kind) + "+" + string(m.Underlying), nil
	}
	if m.Underlying == "" {
		return string(m.Kind), nil
	}
	return string(m.Kind) + "+" + string(m.Underlying), nil
}

type connTransportAttribution interface {
	WeDecentTransportAttribution() (kind, underlying, routerID string)
}

func transportMetadataFromConn(conn net.Conn) TransportMetadata {
	if attributed, ok := conn.(connTransportAttribution); ok {
		kind, underlying, routerID := attributed.WeDecentTransportAttribution()
		return TransportMetadata{
			Kind: TransportKind(kind), Underlying: UnderlyingTransport(underlying), RouteRouterID: routerID,
		}
	}
	return TransportMetadata{Kind: TransportDirectTCP}
}
