package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const maxServeConfigBytes = 64 * 1024

type serveFileConfig struct {
	StateDir                     *string `json:"state"`
	Name                         *string `json:"name"`
	ListenAddr                   *string `json:"listen"`
	DirectTCPUnderlyingTransport *string `json:"direct_tcp_underlay"`
	RFCOMMChannel                *int    `json:"rfcomm_channel"`
	SerialDevice                 *string `json:"serial"`
	Shell                        *string `json:"shell"`
	Discover                     *bool   `json:"discover"`
	MaxConnections               *int    `json:"max_connections"`
	SessionIdleTimeout           *string `json:"session_idle_timeout"`
	SessionMaxDuration           *string `json:"session_max_duration"`
	RelayAddr                    *string `json:"relay"`
	WebRelay                     *string `json:"web_relay"`
	RelaySlots                   *int    `json:"relay_slots"`
	RelayCA                      *string `json:"relay_ca"`
	RelayServerName              *string `json:"relay_server_name"`
	AuthorizationURL             *string `json:"authorization_url"`
	RouteControlListenAddr       *string `json:"route_control_listen"`
	RouteControlTransport        *string `json:"route_control_transport"`
	RouteTunnelListenAddr        *string `json:"route_tunnel_listen"`
	RouteTunnelTransport         *string `json:"route_tunnel_transport"`
	RouteMaxConnections          *int    `json:"route_max_connections"`
}

func init() {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		return
	}
	expanded, err := expandServeConfigArgs(os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "wd-agent:", err)
		os.Exit(1)
	}
	os.Args = append([]string{os.Args[0], "serve"}, expanded...)
}

func expandServeConfigArgs(args []string) ([]string, error) {
	configPath, cliArgs, found, err := extractServeConfigArg(args)
	if err != nil {
		return nil, err
	}
	if !found {
		return append([]string(nil), args...), nil
	}

	configArgs, err := loadServeConfigArgs(configPath)
	if err != nil {
		return nil, fmt.Errorf("load --config: %w", err)
	}
	// File-derived arguments come first so explicitly supplied command-line
	// flags retain their existing override behavior in flag.FlagSet.
	// Changing the listener invalidates a config-file NCM assertion unless
	// the operator explicitly reasserts the underlay on the command line.
	configUnderlay, hasConfigUnderlay, err := serveFlagValue(configArgs, "direct-tcp-underlay")
	if err != nil {
		return nil, err
	}
	configListen, hasConfigListen, err := serveFlagValue(configArgs, "listen")
	if err != nil {
		return nil, err
	}
	cliListen, hasCLIListen, err := serveFlagValue(cliArgs, "listen")
	if err != nil {
		return nil, err
	}
	_, hasCLIUnderlay, err := serveFlagValue(cliArgs, "direct-tcp-underlay")
	if err != nil {
		return nil, err
	}
	expanded := append(append([]string(nil), configArgs...), cliArgs...)
	if hasConfigUnderlay && strings.TrimSpace(configUnderlay) == "usb_ncm" &&
		hasConfigListen && hasCLIListen &&
		strings.TrimSpace(cliListen) != strings.TrimSpace(configListen) && !hasCLIUnderlay {
		insertAt := len(expanded)
		for i := len(configArgs); i < len(expanded); i++ {
			if expanded[i] == "--" {
				insertAt = i
				break
			}
		}
		expanded = append(expanded, "")
		copy(expanded[insertAt+1:], expanded[insertAt:])
		expanded[insertAt] = "--direct-tcp-underlay="
	}
	return expanded, nil
}

func serveFlagValue(args []string, name string) (string, bool, error) {
	flagNames := []string{"--" + name, "-" + name}
	var value string
	found := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		for _, flagName := range flagNames {
			if arg == flagName {
				if i+1 >= len(args) {
					return "", false, fmt.Errorf("%s requires a value", flagName)
				}
				i++
				value = args[i]
				found = true
				break
			}
			if strings.HasPrefix(arg, flagName+"=") {
				value = strings.TrimPrefix(arg, flagName+"=")
				found = true
				break
			}
		}
	}
	return value, found, nil
}

func extractServeConfigArg(args []string) (string, []string, bool, error) {
	out := make([]string, 0, len(args))
	var path string
	found := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			out = append(out, args[i:]...)
			break
		}

		var value string
		matched := false
		switch {
		case arg == "--config" || arg == "-config":
			if i+1 >= len(args) {
				return "", nil, false, errors.New("--config requires a path")
			}
			i++
			value = args[i]
			matched = true
		case strings.HasPrefix(arg, "--config="):
			value = strings.TrimPrefix(arg, "--config=")
			matched = true
		case strings.HasPrefix(arg, "-config="):
			value = strings.TrimPrefix(arg, "-config=")
			matched = true
		}

		if !matched {
			out = append(out, arg)
			continue
		}
		if found {
			return "", nil, false, errors.New("--config may be specified only once")
		}
		value = strings.TrimSpace(value)
		if value == "" {
			return "", nil, false, errors.New("--config path must not be empty")
		}
		path = value
		found = true
	}

	return path, out, found, nil
}

func loadServeConfigArgs(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%q must not be a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q must be a regular file", path)
	}
	if info.Size() <= 0 || info.Size() > maxServeConfigBytes {
		return nil, fmt.Errorf("%q must contain between 1 byte and %d bytes", path, maxServeConfigBytes)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%q must not be group- or world-writable", path)
	}

	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(io.LimitReader(f, maxServeConfigBytes+1))
	dec.DisallowUnknownFields()
	var cfg serveFileConfig
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("decode %q: %w", path, err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("decode %q: multiple JSON values are not allowed", path)
		}
		return nil, fmt.Errorf("decode %q: %w", path, err)
	}
	return cfg.flagArgs(), nil
}

func (cfg serveFileConfig) flagArgs() []string {
	args := make([]string, 0, 21)
	addString := func(name string, value *string) {
		if value != nil {
			args = append(args, "--"+name+"="+*value)
		}
	}
	addBool := func(name string, value *bool) {
		if value != nil {
			args = append(args, "--"+name+"="+strconv.FormatBool(*value))
		}
	}
	addInt := func(name string, value *int) {
		if value != nil {
			args = append(args, "--"+name+"="+strconv.Itoa(*value))
		}
	}

	addString("state", cfg.StateDir)
	addString("name", cfg.Name)
	addString("listen", cfg.ListenAddr)
	addString("direct-tcp-underlay", cfg.DirectTCPUnderlyingTransport)
	addInt("rfcomm-channel", cfg.RFCOMMChannel)
	addString("serial", cfg.SerialDevice)
	addString("shell", cfg.Shell)
	addBool("discover", cfg.Discover)
	addInt("max-connections", cfg.MaxConnections)
	addString("session-idle-timeout", cfg.SessionIdleTimeout)
	addString("session-max-duration", cfg.SessionMaxDuration)
	addString("relay", cfg.RelayAddr)
	addString("web-relay", cfg.WebRelay)
	addInt("relay-slots", cfg.RelaySlots)
	addString("relay-ca", cfg.RelayCA)
	addString("relay-server-name", cfg.RelayServerName)
	addString("authorization-url", cfg.AuthorizationURL)
	addString("route-control-listen", cfg.RouteControlListenAddr)
	addString("route-control-transport", cfg.RouteControlTransport)
	addString("route-tunnel-listen", cfg.RouteTunnelListenAddr)
	addString("route-tunnel-transport", cfg.RouteTunnelTransport)
	addInt("route-max-connections", cfg.RouteMaxConnections)
	return args
}
