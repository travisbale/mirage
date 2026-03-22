package deploy

import (
	"strings"
	"testing"
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
		"data_dir: /var/lib/mirage",
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
