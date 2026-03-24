package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/travisbale/mirage/sdk"
)

func newServerCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Manage miraged servers",
	}
	cmd.AddCommand(
		newServerAddCmd(),
		newServerListCmd(),
		newServerRemoveCmd(),
		newServerDefaultCmd(),
		newServerSwitchCmd(),
	)
	return cmd
}

func newServerAddCmd() *cobra.Command {
	var (
		alias          string
		address        string
		secretHostname string
		token          string
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a miraged server by enrolling with an invite token",
		RunE: func(cmd *cobra.Command, args []string) error {
			// 1. Generate keypair locally.
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return fmt.Errorf("generating key: %w", err)
			}

			// 2. Create CSR.
			csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
				Subject: pkix.Name{CommonName: "pending-enrollment"},
			}, key)
			if err != nil {
				return fmt.Errorf("creating CSR: %w", err)
			}
			csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

			// 3. Enroll via the API.
			enrollResp, err := enroll(address, secretHostname, token, string(csrPEM))
			if err != nil {
				return err
			}

			// 4. Save cert, key, and CA cert.
			dir, err := mirageDir()
			if err != nil {
				return err
			}

			certPath := filepath.Join(dir, alias+".crt")
			keyPath := filepath.Join(dir, alias+".key")
			caPath := filepath.Join(dir, alias+"-ca.crt")

			keyDER, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return fmt.Errorf("marshaling key: %w", err)
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

			if err := os.WriteFile(certPath, []byte(enrollResp.CertPEM), 0644); err != nil {
				return fmt.Errorf("writing cert: %w", err)
			}
			if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
				return fmt.Errorf("writing key: %w", err)
			}
			if err := os.WriteFile(caPath, []byte(enrollResp.CACertPEM), 0644); err != nil {
				return fmt.Errorf("writing CA cert: %w", err)
			}

			// 5. Save server to config.
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			cfg.addServer(Server{
				Alias:          alias,
				Address:        address,
				SecretHostname: secretHostname,
				ClientCertPath: certPath,
				ClientKeyPath:  keyPath,
				ServerCACert:   caPath,
			})
			if cfg.DefaultServer == "" {
				cfg.DefaultServer = alias
			}
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}

			fmt.Printf("Enrolled successfully. Server saved as %q.\n", alias)
			return nil
		},
	}
	cmd.Flags().StringVar(&alias, "alias", "default", "name for this server endpoint")
	cmd.Flags().StringVar(&address, "address", "", "server address (host:port)")
	cmd.Flags().StringVar(&secretHostname, "secret-hostname", "", "secret management hostname")
	cmd.Flags().StringVar(&token, "token", "", "invite token")
	_ = cmd.MarkFlagRequired("address")
	_ = cmd.MarkFlagRequired("secret-hostname")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

// enroll sends a CSR to the server's enrollment endpoint and returns the response.
func enroll(address, secretHostname, token, csrPEM string) (*sdk.EnrollResponse, error) {
	reqBody := sdk.EnrollRequest{Token: token, CSRPEM: csrPEM}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	// Skip TLS verification — we don't have the CA cert yet.
	// The invite token authenticates the server implicitly.
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         secretHostname,
				InsecureSkipVerify: true, //nolint:gosec // enrollment bootstrap
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
			},
		},
	}

	enrollURL := fmt.Sprintf("https://%s%s", secretHostname, sdk.RouteEnroll)
	httpReq, err := http.NewRequest(http.MethodPost, enrollURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("enrollment failed: %s", body)
	}

	var enrollResp sdk.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
		return nil, fmt.Errorf("unable to decode response, expected JSON from API")
	}
	return &enrollResp, nil
}

func newServerListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if len(cfg.Servers) == 0 {
				fmt.Println("No servers configured. Run `mirage server add` to add one.")
				return nil
			}
			rows := make([][]string, len(cfg.Servers))
			for i, s := range cfg.Servers {
				def := ""
				if s.Alias == cfg.DefaultServer {
					def = "*"
				}
				rows[i] = []string{s.Alias, s.Address, s.SecretHostname, def}
			}
			printTable([]string{"ALIAS", "ADDRESS", "SECRET HOSTNAME", "DEFAULT"}, rows)
			return nil
		},
	}
}

func newServerRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <alias>",
		Short: "Remove a server",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if err := cfg.removeServer(args[0]); err != nil {
				return err
			}
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}
			fmt.Printf("Removed server %q\n", args[0])
			return nil
		},
	}
}

func newServerSwitchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "switch <alias>",
		Short: "Switch the active server for the current REPL session",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			return fmt.Errorf("server switch is only available inside the REPL — run `mirage` to start one")
		},
	}
}

func newServerDefaultCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "default <alias>",
		Short: "Set the default server",
		Args:  requireOneArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			if _, err := cfg.findServer(args[0]); err != nil {
				return err
			}
			cfg.DefaultServer = args[0]
			if err := saveConfig(cfg, cfgPath); err != nil {
				return err
			}
			fmt.Printf("Default server set to %q\n", args[0])
			return nil
		},
	}
}
