package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// Client is the top-level structure of ~/.mirage/client.json.
type Client struct {
	DefaultServer string   `json:"default_server"`
	Servers       []Server `json:"servers"`
}

// Server is one configured miraged instance.
type Server struct {
	Alias          string `json:"alias"`
	Address        string `json:"address"`
	SecretHostname string `json:"secret_hostname"`
	ClientCertPath string `json:"client_cert_path"`
	ClientKeyPath  string `json:"client_key_path"`
	ServerCACert   string `json:"server_ca_cert_path"`
}

// mirageDir returns the path to ~/.mirage/, creating it if necessary.
func mirageDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}
	dir := filepath.Join(home, ".mirage")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating config directory: %w", err)
	}
	return dir, nil
}

// defaultConfigPath returns the path to ~/.mirage/client.json.
func defaultConfigPath() (string, error) {
	dir, err := mirageDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "client.json"), nil
}

// resolveConfig loads the client config for the given command, using the
// --config flag if set, otherwise falling back to the default path.
func resolveConfig(cmd *cobra.Command) (*Client, string, error) {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		var err error
		cfgPath, err = defaultConfigPath()
		if err != nil {
			return nil, "", err
		}
	}
	cfg, err := loadConfig(cfgPath)
	return cfg, cfgPath, err
}

// loadConfig reads and parses the client config from path.
// Returns an empty Client (not an error) if the file does not exist.
func loadConfig(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Client{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Client
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// saveConfig atomically writes cfg to path by writing to a temp file then renaming.
func saveConfig(cfg *Client, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("saving config: %w", err)
	}
	return nil
}

// findServer returns the Server for alias, or the default server if alias
// is "". Returns an error if no matching server is found.
func (c *Client) findServer(alias string) (*Server, error) {
	if alias == "" {
		alias = c.DefaultServer
	}
	if alias == "" {
		if len(c.Servers) == 0 {
			return nil, errors.New("no servers configured — run `mirage server add` first")
		}
		return nil, errors.New("no default server set — use --server <alias> or run `mirage server default <alias>`")
	}
	for i := range c.Servers {
		if c.Servers[i].Alias == alias {
			return &c.Servers[i], nil
		}
	}
	return nil, fmt.Errorf("server alias %q not found — run `mirage server list` to see configured servers", alias)
}

// addServer appends or replaces a server entry by alias.
func (c *Client) addServer(server Server) {
	for i := range c.Servers {
		if c.Servers[i].Alias == server.Alias {
			c.Servers[i] = server
			return
		}
	}
	c.Servers = append(c.Servers, server)
}

// removeServer removes the entry with the given alias.
// Returns an error if the alias is not found.
func (c *Client) removeServer(alias string) error {
	for i, s := range c.Servers {
		if s.Alias == alias {
			c.Servers = append(c.Servers[:i], c.Servers[i+1:]...)
			if c.DefaultServer == alias {
				c.DefaultServer = ""
			}
			return nil
		}
	}
	return fmt.Errorf("server alias %q not found", alias)
}
