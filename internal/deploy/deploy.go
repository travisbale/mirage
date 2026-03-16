package deploy

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)


// DeployConfig holds all parameters needed to provision a remote miraged instance.
type DeployConfig struct {
	// SSH connection
	Host       string // e.g. "203.0.113.5" or "203.0.113.5:22"
	SSHUser    string // default "root"
	SSHKeyPath string // path to private key file on the operator's machine

	// miraged config values written to the remote config file
	Domain       string
	ExternalIPv4 string
	HTTPSPort    int  // default 443
	DNSPort      int  // default 53
	AutoCert     bool // default true

	// Remote paths
	RemoteBinaryPath string // default "/usr/local/bin/miraged"
	RemoteConfigDir  string // default "/etc/mirage"

	// Local binary to upload (defaults to the running binary if empty)
	LocalBinaryPath string

	// SecretHostname to write into the remote config.
	// If empty, one is auto-generated and returned in DeployResult.
	SecretHostname string

	// Force deployment even if miraged is already running.
	Force bool
}

// DeployResult contains the outcomes of a successful deployment.
type DeployResult struct {
	SecretHostname string // the API secret hostname on the remote server
	StatusURL      string // https://<SecretHostname>/api/status
}

// DeployService provisions remote miraged instances over SSH.
type DeployService struct {
	// Progress is called after each step completes. May be nil.
	Progress func(step int, total int, name string)
}

// NewDeployService constructs a DeployService.
func NewDeployService() *DeployService {
	return &DeployService{}
}

// Deploy executes the full provisioning sequence against the remote host described
// by cfg. It returns a DeployResult on success or a descriptive error on any step failure.
func (s *DeployService) Deploy(ctx context.Context, cfg DeployConfig) (*DeployResult, error) {
	cfg = applyDefaults(cfg)

	client, err := dialSSH(cfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	result := &DeployResult{
		SecretHostname: cfg.SecretHostname,
		StatusURL:      fmt.Sprintf("https://%s/api/status", cfg.SecretHostname),
	}

	type step struct {
		name string
		fn   func() error
	}
	steps := []step{
		{"check existing installation", func() error { return checkExisting(client, cfg) }},
		{"upload binary", func() error { return uploadBinary(client, cfg) }},
		{"create config directory", func() error { return createDir(client, cfg.RemoteConfigDir) }},
		{"create data directory", func() error { return createDir(client, remoteDataDir) }},
		{"write config file", func() error { return writeConfig(client, cfg) }},
		{"write systemd unit", func() error { return writeSystemdUnit(client, cfg) }},
		{"enable and start service", func() error { return startService(client) }},
		{"wait for daemon to become healthy", func() error { return waitForDaemon(ctx, client) }},
	}

	for i, st := range steps {
		if s.Progress != nil {
			s.Progress(i+1, len(steps), st.name)
		}
		if err := st.fn(); err != nil {
			return nil, fmt.Errorf("%s: %w", st.name, err)
		}
	}

	return result, nil
}

// remoteDataDir is where miraged stores its database and generated certificates.
const remoteDataDir = "/var/lib/mirage"

// waitForDaemon polls systemctl over SSH until miraged reports active or the
// context deadline is reached. Using SSH avoids the need for a client
// certificate to reach the mTLS-protected management API.
func waitForDaemon(ctx context.Context, client *ssh.Client) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := runCmd(client, "systemctl is-active miraged 2>/dev/null || true")
		if strings.TrimSpace(out) == "active" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("timed out after 30s waiting for miraged to become active")
}

// dialSSH opens an SSH connection using a private key file.
func dialSSH(cfg DeployConfig) (*ssh.Client, error) {
	keyBytes, err := os.ReadFile(cfg.SSHKeyPath)
	if err != nil {
		return nil, fmt.Errorf("reading SSH key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing SSH key: %w", err)
	}
	addr := cfg.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "22")
	}
	sshCfg := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // TOFU hardening is a follow-up
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", addr, sshCfg)
}

// runCmd runs a shell command over SSH and returns combined stdout+stderr.
func runCmd(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// checkExisting returns an error if miraged is already active on the remote
// host and cfg.Force is false.
func checkExisting(client *ssh.Client, cfg DeployConfig) error {
	out, _ := runCmd(client, "systemctl is-active miraged 2>/dev/null || true")
	if strings.TrimSpace(out) == "active" && !cfg.Force {
		return fmt.Errorf("miraged is already running on %s — stop it first or use --force", cfg.Host)
	}
	return nil
}

// createDir creates a directory on the remote host with mode 0700 using SFTP.
func createDir(client *ssh.Client, path string) error {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("opening SFTP session: %w", err)
	}
	defer sftpClient.Close()
	if err := sftpClient.MkdirAll(path); err != nil {
		return fmt.Errorf("creating directory %s: %w", path, err)
	}
	return sftpClient.Chmod(path, 0700)
}

// uploadBinary copies the local miraged binary to the remote host using SFTP.
func uploadBinary(client *ssh.Client, cfg DeployConfig) error {
	localPath := cfg.LocalBinaryPath
	if localPath == "" {
		var err error
		localPath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("finding local binary: %w", err)
		}
	}

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("opening SFTP session: %w", err)
	}
	defer sftpClient.Close()

	src, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer src.Close()

	if err := sftpClient.MkdirAll(filepath.Dir(cfg.RemoteBinaryPath)); err != nil {
		return fmt.Errorf("creating remote binary directory: %w", err)
	}

	dst, err := sftpClient.OpenFile(cfg.RemoteBinaryPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("creating remote file %s: %w", cfg.RemoteBinaryPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("copying binary: %w", err)
	}

	_, err = runCmd(client, fmt.Sprintf("chmod 755 %s", cfg.RemoteBinaryPath))
	return err
}

// startService reloads systemd and enables + starts the miraged unit in one SSH session.
func startService(client *ssh.Client) error {
	out, err := runCmd(client, "systemctl daemon-reload && systemctl enable miraged && systemctl start miraged")
	if err != nil {
		return fmt.Errorf("starting miraged: %s", strings.TrimSpace(out))
	}
	return nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg DeployConfig) DeployConfig {
	if cfg.SSHUser == "" {
		cfg.SSHUser = "root"
	}
	if cfg.HTTPSPort == 0 {
		cfg.HTTPSPort = 443
	}
	if cfg.DNSPort == 0 {
		cfg.DNSPort = 53
	}
	if cfg.RemoteBinaryPath == "" {
		cfg.RemoteBinaryPath = "/usr/local/bin/miraged"
	}
	if cfg.RemoteConfigDir == "" {
		cfg.RemoteConfigDir = "/etc/mirage"
	}
	if cfg.SecretHostname == "" {
		cfg.SecretHostname = generateSecretHostname(cfg.Domain)
	}
	return cfg
}

// generateSecretHostname produces a random subdomain like "a3f9c2.mgmt.attacker.com".
func generateSecretHostname(baseDomain string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x.mgmt.%s", b, baseDomain)
}
