package deploy

import (
	"os"
	"strings"
	"testing"

	"github.com/travisbale/mirage/internal/config"
)

func TestGenerateSecretHostname(t *testing.T) {
	domain := "attacker.com"
	hostname := GenerateSecretHostname(domain)

	if !strings.HasSuffix(hostname, ".mgmt."+domain) {
		t.Errorf("hostname %q does not end in .mgmt.%s", hostname, domain)
	}

	// Should be unique across calls.
	other := GenerateSecretHostname(domain)
	if hostname == other {
		t.Error("GenerateSecretHostname returned identical values on two calls")
	}
}

func testConfig() Config {
	return Config{
		Domain:           "attacker.com",
		ExternalIPv4:     "203.0.113.5",
		HTTPSPort:        443,
		DNSPort:          53,
		DataDir:          config.DefaultDataDir,
		PhishletsDir:     "/etc/mirage/phishlets",
		SecretHostname:   "abc123.mgmt.attacker.com",
		RemoteBinaryPath: "/usr/local/bin/miraged",
		RemoteConfigDir:  "/etc/mirage",
	}
}

func TestRenderConfig(t *testing.T) {
	out, err := renderConfig(testConfig())
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}

	for _, want := range []string{
		"domain: attacker.com",
		"external_ipv4: 203.0.113.5",
		"https_port: 443",
		"self_signed: true",
		"data_dir: /var/lib/mirage",
		"phishlets_dir: /etc/mirage/phishlets",
		"secret_hostname: abc123.mgmt.attacker.com",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("renderConfig output missing %q\ngot:\n%s", want, out)
		}
	}

	for _, bad := range []string{"autocert", "bind_ipv4", "blacklist", "botguard"} {
		if strings.Contains(out, bad) {
			t.Errorf("renderConfig output contains unexpected field %q", bad)
		}
	}
}

// TestRenderConfig_ParseableByDaemon verifies the generated config can be
// loaded and validated by the real config package. This catches field name
// mismatches between the template and the config struct.
func TestRenderConfig_ParseableByDaemon(t *testing.T) {
	out, err := renderConfig(testConfig())
	if err != nil {
		t.Fatalf("renderConfig: %v", err)
	}

	tmpFile := t.TempDir() + "/miraged.yaml"
	if err := os.WriteFile(tmpFile, []byte(out), 0600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load failed on generated config: %v\ngenerated:\n%s", err, out)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("config.Validate failed on generated config: %v\ngenerated:\n%s", err, out)
	}

	if cfg.Domain != "attacker.com" {
		t.Errorf("Domain: got %q, want %q", cfg.Domain, "attacker.com")
	}
	if !cfg.SelfSigned {
		t.Error("expected SelfSigned to be true")
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	out, err := renderSystemdUnit(testConfig())
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
