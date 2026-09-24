package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"wedecent.com/wedecent/internal/updateinfo"
)

const maxKeyFileBytes = 96

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wd-update-manifest:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected create, verify, or key-info command")
	}
	switch args[0] {
	case "create":
		return runCreate(args[1:], stdout)
	case "verify":
		return runVerify(args[1:], stdout)
	case "key-info":
		return runKeyInfo(args[1:], stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runKeyInfo(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("key-info", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	publicKeyPath := flags.String("public-key", "", "canonical update public key file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("key-info accepts no positional arguments")
	}
	if *publicKeyPath == "" {
		return errors.New("--public-key is required")
	}
	keyBytes, err := readBoundedRegular(*publicKeyPath, maxKeyFileBytes)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	publicKey, err := updateinfo.DecodePublicKey(keyBytes)
	if err != nil {
		return err
	}
	fingerprint, err := updateinfo.PublicKeyFingerprint(publicKey)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "fingerprint=sha256:%s\n", fingerprint)
	return err
}

func runCreate(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sequence := flags.Uint64("sequence", 0, "stable manifest sequence")
	version := flags.String("version", "", "stable version, including v prefix")
	publishedAt := flags.String("published-at", "", "canonical UTC RFC3339 timestamp")
	releaseSHA := flags.String("release-sha256", "", "release archive SHA-256")
	installerSHA := flags.String("installer-sha256", "", "installer archive SHA-256")
	out := flags.String("out", "", "exclusive output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("create accepts no positional arguments")
	}
	if *out == "" {
		return errors.New("--out is required")
	}

	manifest := updateinfo.Manifest{
		Schema:          updateinfo.ManifestSchemaV1,
		Channel:         updateinfo.StableChannel,
		Sequence:        *sequence,
		Version:         *version,
		PublishedAt:     *publishedAt,
		ReleaseURL:      fmt.Sprintf("https://%s/windows/%s/wedecent-%s-windows-amd64.zip", updateinfo.DownloadHost, *version, *version),
		ReleaseSHA256:   *releaseSHA,
		InstallerURL:    fmt.Sprintf("https://%s/windows/%s/wedecent-%s-windows-installer.zip", updateinfo.DownloadHost, *version, *version),
		InstallerSHA256: *installerSHA,
	}
	encoded, err := updateinfo.EncodeCanonical(manifest)
	if err != nil {
		return err
	}
	if err := writeExclusive(*out, encoded, 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "sequence=%d\nversion=%s\n", manifest.Sequence, manifest.Version)
	return err
}

func runVerify(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	publicKeyPath := flags.String("public-key", "", "canonical update public key file")
	manifestPath := flags.String("manifest", "", "canonical manifest file")
	signaturePath := flags.String("signature", "", "detached signature file")
	currentVersion := flags.String("current-version", "", "optional current stable version")
	currentSequenceText := flags.String("current-sequence", "", "optional highest accepted sequence")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("verify accepts no positional arguments")
	}
	if *publicKeyPath == "" || *manifestPath == "" || *signaturePath == "" {
		return errors.New("--public-key, --manifest, and --signature are required")
	}

	keyBytes, err := readBoundedRegular(*publicKeyPath, maxKeyFileBytes)
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	publicKey, err := updateinfo.DecodePublicKey(keyBytes)
	if err != nil {
		return err
	}
	manifestBytes, err := readBoundedRegular(*manifestPath, updateinfo.MaxManifestBytes)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	signatureBytes, err := readBoundedRegular(*signaturePath, 128)
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	manifest, err := updateinfo.Verify(publicKey, manifestBytes, signatureBytes)
	if err != nil {
		return err
	}

	if (*currentVersion == "") != (*currentSequenceText == "") {
		return errors.New("--current-version and --current-sequence must be provided together")
	}
	if *currentVersion != "" {
		currentSequence, err := strconv.ParseUint(*currentSequenceText, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --current-sequence: %w", err)
		}
		if err := updateinfo.CheckAdvance(*currentVersion, currentSequence, manifest); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "sequence=%d\nversion=%s\n", manifest.Sequence, manifest.Version)
	return err
}

func readBoundedRegular(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("path is not a regular non-symlink file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > limit {
		return nil, errors.New("file size is invalid")
	}
	return data, nil
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if info, err := os.Lstat(parent); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output parent must be an existing non-symlink directory")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync output: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	ok = true
	return nil
}
