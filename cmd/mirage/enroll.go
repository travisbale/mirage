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

func newEnrollCmd() *cobra.Command {
	var (
		serverAddr     string
		secretHostname string
		token          string
		alias          string
	)

	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll as a new operator using an invite token",
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

			// 3. POST to the enroll endpoint.
			reqBody := sdk.EnrollRequest{
				Token:  token,
				CSRPEM: string(csrPEM),
			}
			bodyBytes, _ := json.Marshal(reqBody)

			enrollURL := fmt.Sprintf("https://%s%s", secretHostname, sdk.RouteEnroll)

			// The server's TLS cert is signed by the proxy CA, which we don't
			// have yet. Skip verification for enrollment only — the invite
			// token authenticates the server implicitly.
			dialAddr := serverAddr
			httpClient := &http.Client{
				Timeout: 30 * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         secretHostname,
						InsecureSkipVerify: true, //nolint:gosec // enrollment bootstrap
					},
					DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
						return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, dialAddr)
					},
				},
			}

			httpReq, err := http.NewRequest(http.MethodPost, enrollURL, bytes.NewReader(bodyBytes))
			if err != nil {
				return fmt.Errorf("building request: %w", err)
			}
			httpReq.Header.Set("Content-Type", "application/json")

			resp, err := httpClient.Do(httpReq)
			if err != nil {
				return fmt.Errorf("enrollment request failed: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				return fmt.Errorf("enrollment failed: %s", body)
			}

			var enrollResp sdk.EnrollResponse
			if err := json.NewDecoder(resp.Body).Decode(&enrollResp); err != nil {
				return fmt.Errorf("decoding response: %w", err)
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

			// 5. Auto-add server to client config.
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				cfgPath = filepath.Join(dir, "client.json")
			}
			cfg, err := loadConfig(cfgPath)
			if err != nil {
				cfg = &Client{}
			}

			cfg.Servers = append(cfg.Servers, Server{
				Alias:          alias,
				Address:        "https://" + serverAddr,
				SecretHostname: secretHostname,
				ClientCertPath: certPath,
				ClientKeyPath:  keyPath,
				ServerCACert:   caPath,
			})
			if cfg.DefaultServer == "" {
				cfg.DefaultServer = alias
			}
			if err := saveConfig(cfg, cfgPath); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}

			fmt.Printf("Enrolled successfully. Server saved as %q.\n", alias)
			fmt.Printf("  cert: %s\n", certPath)
			fmt.Printf("  key:  %s\n", keyPath)
			fmt.Printf("  ca:   %s\n", caPath)
			return nil
		},
	}

	cmd.Flags().StringVar(&serverAddr, "server", "", "server address (host:port)")
	cmd.Flags().StringVar(&secretHostname, "secret-hostname", "", "server's secret API hostname")
	cmd.Flags().StringVar(&token, "token", "", "invite token")
	cmd.Flags().StringVar(&alias, "alias", "", "local alias for this server")
	_ = cmd.MarkFlagRequired("server")
	_ = cmd.MarkFlagRequired("secret-hostname")
	_ = cmd.MarkFlagRequired("token")
	_ = cmd.MarkFlagRequired("alias")
	return cmd
}
