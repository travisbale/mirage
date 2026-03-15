package deploy

import (
	"strings"
	"testing"
)

func TestApplyDefaults(t *testing.T) {
	cfg := applyDefaults(DeployConfig{Domain: "attacker.com"})

	if cfg.SSHUser != "root" {
		t.Errorf("SSHUser: got %q, want %q", cfg.SSHUser, "root")
	}
	if cfg.HTTPSPort != 443 {
		t.Errorf("HTTPSPort: got %d, want 443", cfg.HTTPSPort)
	}
	if cfg.DNSPort != 53 {
		t.Errorf("DNSPort: got %d, want 53", cfg.DNSPort)
	}
	if cfg.RemoteBinaryPath != "/usr/local/bin/miraged" {
		t.Errorf("RemoteBinaryPath: got %q, want %q", cfg.RemoteBinaryPath, "/usr/local/bin/miraged")
	}
	if cfg.RemoteConfigDir != "/etc/mirage" {
		t.Errorf("RemoteConfigDir: got %q, want %q", cfg.RemoteConfigDir, "/etc/mirage")
	}
	if cfg.SecretHostname == "" {
		t.Error("SecretHostname should be auto-generated when empty")
	}
}

func TestApplyDefaults_PreservesExplicitValues(t *testing.T) {
	cfg := applyDefaults(DeployConfig{
		SSHUser:        "ubuntu",
		HTTPSPort:      8443,
		SecretHostname: "explicit.mgmt.example.com",
	})

	if cfg.SSHUser != "ubuntu" {
		t.Errorf("SSHUser: got %q, want %q", cfg.SSHUser, "ubuntu")
	}
	if cfg.HTTPSPort != 8443 {
		t.Errorf("HTTPSPort: got %d, want 8443", cfg.HTTPSPort)
	}
	if cfg.SecretHostname != "explicit.mgmt.example.com" {
		t.Errorf("SecretHostname: got %q, want explicit.mgmt.example.com", cfg.SecretHostname)
	}
}

func TestGenerateSecretHostname(t *testing.T) {
	domain := "attacker.com"
	hostname := generateSecretHostname(domain)

	if !strings.HasSuffix(hostname, ".mgmt."+domain) {
		t.Errorf("hostname %q does not end in .mgmt.%s", hostname, domain)
	}

	// Should be unique across calls.
	other := generateSecretHostname(domain)
	if hostname == other {
		t.Error("generateSecretHostname returned identical values on two calls")
	}
}

func TestRenderConfig(t *testing.T) {
	cfg := DeployConfig{
		Domain:          "attacker.com",
		ExternalIPv4:    "203.0.113.5",
		HTTPSPort:       443,
		DNSPort:         53,
		AutoCert:        true,
		SecretHostname:  "abc123.mgmt.attacker.com",
		RemoteConfigDir: "/etc/mirage",
	}

	out, err := renderConfig(cfg)
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}

	for _, want := range []string{
		"domain: attacker.com",
		"external_ipv4: 203.0.113.5",
		"https_port: 443",
		"secret_hostname: abc123.mgmt.attacker.com",
		"client_ca_cert_path: /var/lib/mirage/api-ca.crt",
		"db_path: /var/lib/mirage/data.db",
		"phishlets_dir: /etc/mirage/phishlets",
		"autocert: true",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderConfig output missing %q", want)
		}
	}

	for _, bad := range []string{"bind_ipv4", "blacklist", "botguard", "client_ca_cert:"} {
		if strings.Contains(out, bad) {
			t.Errorf("renderConfig output contains unexpected field %q", bad)
		}
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	cfg := DeployConfig{
		RemoteBinaryPath: "/usr/local/bin/miraged",
		RemoteConfigDir:  "/etc/mirage",
	}

	out, err := renderSystemdUnit(cfg)
	if err != nil {
		t.Fatalf("renderSystemdUnit: %v", err)
	}

	for _, want := range []string{
		"ExecStart=/usr/local/bin/miraged --config /etc/mirage/miraged.yaml",
		"WantedBy=multi-user.target",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=true",
		"ReadWritePaths=/etc/mirage /var/lib/mirage",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderSystemdUnit output missing %q", want)
		}
	}
}
