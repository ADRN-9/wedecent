//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"wedecent.com/wedecent/internal/identity"
	"wedecent.com/wedecent/internal/trust"
	"wedecent.com/wedecent/internal/winservice"
)

const defaultWindowsServiceName = "WeDecentAgent"

var (
	kernel32Service    = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32Service.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32Service.NewProc("SetConsoleMode")
)

func runServiceCommand(args []string) error {
	if len(args) == 0 {
		serviceUsage()
		return errors.New("service subcommand is required")
	}
	switch args[0] {
	case "install":
		return runServiceInstall(args[1:])
	case "run":
		return runServiceRun(args[1:])
	case "start":
		return runServiceStart(args[1:])
	case "stop":
		return runServiceStop(args[1:])
	case "status":
		return runServiceStatus(args[1:])
	case "uninstall":
		return runServiceUninstall(args[1:])
	default:
		serviceUsage()
		return fmt.Errorf("unknown service subcommand %q", args[0])
	}
}

func runServiceInstall(args []string) error {
	fs := flag.NewFlagSet("service install", flag.ContinueOnError)
	serviceName := fs.String("service-name", defaultWindowsServiceName, "Windows service name")
	displayName := fs.String("display-name", "WeDecent Agent", "Windows service display name")
	account := fs.String("account", "", `dedicated standard service account, e.g. .\WeDecentSvc`)
	accountPasswordStdin := fs.Bool("account-password-stdin", false, "read the service account password from standard input")
	stateDir := fs.String("state", defaultServiceStateDir(), "machine-wide agent state directory")
	deviceName := fs.String("name", hostname(), "device display name")
	listenAddr := fs.String("listen", "", "TCP listen address; empty disables inbound TCP")
	webRelay := fs.String("web-relay", "https://relay.wedecent.com", "serverless WebSocket relay URL")
	relaySlots := fs.Int("relay-slots", 4, "number of parked outbound relay connections")
	shell := fs.String("shell", defaultShell(), "absolute shell path")
	automatic := fs.Bool("automatic", true, "start the service automatically at boot")
	startNow := fs.Bool("start", true, "start the service after installation")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*account) == "" {
		return errors.New("--account is required; use a dedicated standard Windows account")
	}
	if isBuiltInServiceAccount(*account) {
		return errors.New("refusing built-in service account; use a dedicated standard Windows account")
	}
	if *relaySlots < 1 || *relaySlots > 32 {
		return errors.New("relay-slots must be between 1 and 32")
	}
	if *listenAddr == "" && *webRelay == "" {
		return errors.New("at least one of --listen or --web-relay must be configured")
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}

	id, err := identity.Ensure(*stateDir, *deviceName)
	if err != nil {
		return err
	}
	if _, err := trust.Open(filepath.Join(*stateDir, "trusted-clients.json")); err != nil {
		return err
	}
	pairSecret, err := trust.RotatePairingSecret(*stateDir)
	if err != nil {
		return err
	}

	if err := winservice.RestrictDirectory(*stateDir, *account); err != nil {
		return err
	}

	password := ""
	if !strings.HasSuffix(strings.TrimSpace(*account), "$") {
		if *accountPasswordStdin {
			password, err = readServicePassword(os.Stdin)
		} else {
			password, err = readHiddenLine("Service account password: ")
		}
		if err != nil {
			return err
		}
		if password == "" {
			return errors.New("service account password cannot be empty")
		}
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve wd-agent executable: %w", err)
	}
	serviceArgs := []string{
		"service", "run",
		"--service-name=" + *serviceName,
		"--state=" + *stateDir,
		"--name=" + *deviceName,
		"--listen=" + *listenAddr,
		"--web-relay=" + *webRelay,
		fmt.Sprintf("--relay-slots=%d", *relaySlots),
		"--shell=" + *shell,
	}
	if err := winservice.Install(winservice.InstallOptions{
		Name:        *serviceName,
		DisplayName: *displayName,
		Description: "WeDecent outbound-only remote terminal agent",
		Account:     *account,
		Password:    password,
		Executable:  executable,
		Arguments:   serviceArgs,
		Automatic:   *automatic,
	}); err != nil {
		return err
	}

	fp, _ := identity.FingerprintPublicKey(id.PublicKey)
	fmt.Printf("Service installed: %s\n", *serviceName)
	fmt.Printf("Service account:   %s\n", *account)
	fmt.Printf("State directory:   %s\n", *stateDir)
	fmt.Printf("Device ID:         %s\n", id.ID)
	fmt.Printf("Fingerprint:       %s\n", fp)
	fmt.Printf("Pair secret:       %s\n", pairSecret)
	fmt.Println("\nThe pair secret is single-use. Keep it private.")
	if *startNow {
		if err := winservice.Start(*serviceName); err != nil {
			return fmt.Errorf("service installed but failed to start: %w; inspect %s for runtime error details", err, filepath.Join(*stateDir, "service.log"))
		}
		fmt.Println("Service started.")
	}
	return nil
}

func runServiceRun(args []string) error {
	serviceName, serveArgs, err := extractServiceName(args)
	if err != nil {
		return err
	}
	cfg, err := parseServeConfig(serveArgs)
	if err != nil {
		return err
	}
	logFile, err := openServiceLog(cfg.StateDir)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logger := slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)
	return winservice.Run(serviceName, func(ctx context.Context) error {
		logger.Info("service starting", "service", serviceName, "state", cfg.StateDir)
		err := runAgent(ctx, cfg)
		if err != nil {
			logger.Error("service stopped with error", "error", err)
		} else {
			logger.Info("service stopped")
		}
		return err
	})
}

func runServiceStart(args []string) error {
	name, err := serviceNameOnlyFlags("service start", args)
	if err != nil {
		return err
	}
	return winservice.Start(name)
}

func runServiceStop(args []string) error {
	name, err := serviceNameOnlyFlags("service stop", args)
	if err != nil {
		return err
	}
	return winservice.Stop(name)
}

func runServiceStatus(args []string) error {
	name, err := serviceNameOnlyFlags("service status", args)
	if err != nil {
		return err
	}
	st, err := winservice.Query(name)
	if err != nil {
		return err
	}
	fmt.Printf("%s\t%s\tpid=%d\texit=%d\n", name, st.State, st.ProcessID, st.ExitCode)
	return nil
}

func runServiceUninstall(args []string) error {
	name, err := serviceNameOnlyFlags("service uninstall", args)
	if err != nil {
		return err
	}
	return winservice.Uninstall(name)
}

func serviceNameOnlyFlags(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	serviceName := fs.String("service-name", defaultWindowsServiceName, "Windows service name")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	return *serviceName, nil
}

func extractServiceName(args []string) (string, []string, error) {
	name := defaultWindowsServiceName
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--service-name" {
			if i+1 >= len(args) {
				return "", nil, errors.New("--service-name requires a value")
			}
			name = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(arg, "--service-name=") {
			name = strings.TrimPrefix(arg, "--service-name=")
			continue
		}
		rest = append(rest, arg)
	}
	if strings.TrimSpace(name) == "" {
		return "", nil, errors.New("service name cannot be empty")
	}
	return name, rest, nil
}

func defaultServiceStateDir() string {
	base := strings.TrimSpace(os.Getenv("ProgramData"))
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "WeDecent", "agent")
}

func openServiceLog(stateDir string) (*os.File, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create service state directory: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open service log: %w", err)
	}
	return f, nil
}

func isBuiltInServiceAccount(account string) bool {
	n := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(account), " ", ""))
	switch n {
	case "localsystem", ".\\localsystem", "ntauthority\\system", "system",
		"localservice", "ntauthority\\localservice",
		"networkservice", "ntauthority\\networkservice":
		return true
	default:
		return false
	}
}

func readHiddenLine(prompt string) (string, error) {
	const enableEchoInput = 0x0004
	h := uintptr(os.Stdin.Fd())
	var mode uint32
	r1, _, callErr := procGetConsoleMode.Call(h, uintptr(unsafe.Pointer(&mode)))
	if r1 == 0 {
		return "", fmt.Errorf("GetConsoleMode: %w", callErr)
	}
	r1, _, callErr = procSetConsoleMode.Call(h, uintptr(mode&^enableEchoInput))
	if r1 == 0 {
		return "", fmt.Errorf("disable console echo: %w", callErr)
	}
	defer procSetConsoleMode.Call(h, uintptr(mode))
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func serviceUsage() {
	fmt.Fprintln(os.Stderr, `Usage: wd-agent service <command> [options]

Commands:
  install      Install the native Windows service under a dedicated account
  start        Start the Windows service
  stop         Stop the Windows service
  status       Show Windows service status
  uninstall    Stop and remove the Windows service
  run          Internal SCM entrypoint; do not invoke manually`)
}
