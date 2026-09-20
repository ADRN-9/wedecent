//go:build js || plan9 || wasip1

package localipc

import (
	"context"
	"net"
)

func Endpoint() (string, error) { return "", ErrUnsupportedPlatform }

func Listen() (net.Listener, error) { return nil, ErrUnsupportedPlatform }

func Dial(context.Context) (net.Conn, error) { return nil, ErrUnsupportedPlatform }
