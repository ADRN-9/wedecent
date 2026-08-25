package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"wedecent.com/wedecent/internal/relay"
)

func main() {
	fs := flag.NewFlagSet("wd-relay", flag.ExitOnError)
	listenAddr := fs.String("listen", ":443", "TLS listen address")
	certFile := fs.String("cert", "", "TLS certificate PEM")
	keyFile := fs.String("key", "", "TLS private key PEM")
	maxConnections := fs.Int("max-connections", 10000, "maximum concurrent outer connections")
	maxSlots := fs.Int("max-slots-per-device", 8, "maximum parked outbound slots per device")
	slotTTL := fs.Duration("slot-ttl", 5*time.Minute, "maximum age of an unused relay slot")
	fs.Parse(os.Args[1:])
	if *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "wd-relay: --cert and --key are required")
		os.Exit(2)
	}
	if *maxConnections < 1 || *maxConnections > 1_000_000 {
		fatal(errors.New("max-connections out of range"))
	}
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fatal(err)
	}
	ln, err := tls.Listen("tcp", *listenAddr, relay.TLSConfig(cert))
	if err != nil {
		fatal(err)
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = ln.Close() }()

	server := &relay.Server{Broker: relay.NewBroker(*maxSlots, *slotTTL), Logger: slog.Default()}
	sem := make(chan struct{}, *maxConnections)
	slog.Info("WeDecent relay listening", "address", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			fatal(err)
		}
		select {
		case sem <- struct{}{}:
			go func(c net.Conn) {
				defer func() { <-sem }()
				server.ServeConn(c)
			}(conn)
		default:
			_ = conn.Close()
			slog.Warn("relay connection limit reached")
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wd-relay:", err)
	os.Exit(1)
}
