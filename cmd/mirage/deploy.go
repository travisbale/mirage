package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/internal/config"
	"github.com/travisbale/mirage/internal/deploy"
)

func newDeployCmd() *cobra.Command {
	var (
		domain     string
		externalIP string
		httpsPort  int
		dnsPort    int
		sshKey     string
		sshUser    string
		binary     string
		configDir  string
		secretHost string
		alias      string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "deploy <host>",
		Short: "Provision a remote miraged instance over SSH",
		Long: `Deploy copies the miraged binary to a remote Linux server over SSH,
writes a config file and systemd unit, starts the service, and waits for it to become healthy.

After a successful deploy, add the server with:
  mirage server add --alias <alias> ...`,
		Args: requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			host := args[0]

			if sshKey == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("resolving home directory: %w", err)
				}
				sshKey = filepath.Join(home, ".ssh", "id_rsa")
			}

			if secretHost == "" {
				secretHost = deploy.GenerateSecretHostname(domain)
			}

			cfg := deploy.DeployConfig{
				Host:             host,
				SSHUser:          sshUser,
				SSHKeyPath:       sshKey,
				Domain:           domain,
				ExternalIPv4:     externalIP,
				HTTPSPort:        httpsPort,
				DNSPort:          dnsPort,
				AutoCert:         true,
				RemoteBinaryPath: "/usr/local/bin/miraged",
				RemoteConfigDir:  configDir,
				LocalBinaryPath:  binary,
				SecretHostname:   secretHost,
				Force:            force,
			}

			svc := deploy.NewDeployService()
			svc.Progress = func(step, total int, name string) {
				fmt.Printf("[%d/%d] %s... ", step, total, name)
			}

			fmt.Printf("Deploying miraged to %s\n\n", host)

			result, err := svc.Deploy(cmd.Context(), cfg)
			if err != nil {
				fmt.Println("FAILED")
				return err
			}
			fmt.Println("OK")
			fmt.Println()
			fmt.Printf("Secret hostname : %s\n", result.SecretHostname)
			fmt.Printf("Status URL      : %s\n", result.StatusURL)
			fmt.Println()
			fmt.Println("Next step — download operator certs from the remote server,")
			fmt.Println("then register it with:")
			fmt.Printf("  mirage server add --alias %s --address https://%s \\\n", alias, host)
			fmt.Printf("    --secret-hostname %s \\\n", result.SecretHostname)
			fmt.Printf("    --cert /var/lib/mirage/operator.crt \\\n")
			fmt.Printf("    --key /var/lib/mirage/operator.key \\\n")
			fmt.Printf("    --ca-cert /var/lib/mirage/api-ca.crt\n")

			return nil
		},
	}

	cmd.Flags().StringVar(&domain, "domain", "", "base domain for the phishing server (required)")
	cmd.Flags().StringVar(&externalIP, "ip", "", "external IPv4 address of the server (required)")
	cmd.Flags().IntVar(&httpsPort, "https-port", config.DefaultHTTPSPort, "HTTPS listen port")
	cmd.Flags().IntVar(&dnsPort, "dns-port", config.DefaultDNSPort, "DNS listen port")
	cmd.Flags().StringVar(&sshKey, "ssh-key", "", "path to SSH private key (default: ~/.ssh/id_rsa)")
	cmd.Flags().StringVar(&sshUser, "ssh-user", "root", "SSH username")
	cmd.Flags().StringVar(&binary, "binary", "", "local miraged binary to upload (default: current executable)")
	cmd.Flags().StringVar(&configDir, "config-dir", "/etc/mirage", "remote config directory")
	cmd.Flags().StringVar(&secretHost, "secret-hostname", "", "secret management hostname (auto-generated if empty)")
	cmd.Flags().StringVar(&alias, "alias", "prod", "alias to use in the server add command shown after deploy")
	cmd.Flags().BoolVar(&force, "force", false, "deploy even if miraged is already running")
	_ = cmd.MarkFlagRequired("domain")
	_ = cmd.MarkFlagRequired("ip")

	return cmd
}
