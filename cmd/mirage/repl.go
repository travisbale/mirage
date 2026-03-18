package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"github.com/chzyer/readline"
	"github.com/spf13/cobra"
)

func newREPLCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "repl",
		Short: "Start an interactive REPL session (default when no command is given)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, cfgPath, err := resolveConfig(cmd)
			if err != nil {
				return err
			}
			alias, _ := cmd.Flags().GetString("server")
			if alias == "" {
				alias = cfg.DefaultServer
			}
			return runREPL(cmd.Context(), alias, cfgPath)
		},
	}
}

func runREPL(ctx context.Context, serverAlias, cfgPath string) error {
	histPath, err := historyPath()
	if err != nil {
		histPath = "" // history is optional
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            prompt(serverAlias, false),
		HistoryFile:       histPath,
		HistoryLimit:      500,
		AutoComplete:      buildCompleter(),
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return fmt.Errorf("initialising readline: %w", err)
	}
	defer rl.Close()

	fmt.Print(`
░  ░░░░  ░░      ░░       ░░░░      ░░░░      ░░░        ░
▒   ▒▒   ▒▒▒▒  ▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒▒▒▒
▓        ▓▓▓▓  ▓▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓   ▓▓      ▓▓▓
█  █  █  ████  ████  ███  ███        ██  ████  ██  ███████
█  ████  ██      ██  ████  ██  ████  ███      ███        █

 AiTM Phishing Framework  •  v` + Version + `
──────────────────────────────────────────────────────────

`)

	if serverAlias == "" {
		fmt.Println("No server configured. Run `server add` to connect to a miraged instance.")
		fmt.Println()
	}

	degraded := false
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := rl.Readline()
		if errors.Is(err, readline.ErrInterrupt) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil
		}

		args := tokenize(line)
		if len(args) == 0 {
			continue
		}

		switch args[0] {
		case "exit", "quit":
			return nil

		case "server":
			if len(args) > 1 && args[1] == "switch" {
				if len(args) < 3 {
					fmt.Fprintln(os.Stderr, "usage: server switch <alias>")
					continue
				}
				serverAlias = args[2]
				rl.SetPrompt(prompt(serverAlias, false))
				fmt.Printf("Switched to server %q\n", serverAlias)
				continue
			}
			fallthrough

		default:
			ok := execCommand(args, serverAlias, cfgPath)
			if serverAlias == "" && ok {
				if cfg, err := loadConfig(cfgPath); err == nil && cfg.DefaultServer != "" {
					serverAlias = cfg.DefaultServer
				}
			}
			degraded = !ok
			rl.SetPrompt(prompt(serverAlias, degraded))
		}
	}
}

// execCommand runs args as a mirage CLI command, returning true on success.
func execCommand(args []string, serverAlias, cfgPath string) bool {
	full := make([]string, 0, len(args)+4)
	full = append(full, args...)
	if serverAlias != "" {
		full = append(full, "--server", serverAlias)
	}
	if cfgPath != "" {
		full = append(full, "--config", cfgPath)
	}

	cmd := newRootCmd()
	cmd.SetArgs(full)
	// Suppress cobra's automatic error printing — we handle it via the prompt.
	cmd.SilenceErrors = true
	err := cmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return false
	}
	return true
}

// prompt returns the readline prompt string, with a "!" suffix when degraded.
func prompt(alias string, degraded bool) string {
	if alias == "" {
		return "mirage> "
	}
	if degraded {
		return fmt.Sprintf("mirage [%s!]> ", alias)
	}
	return fmt.Sprintf("mirage [%s]> ", alias)
}

// historyPath returns ~/.mirage/history.
func historyPath() (string, error) {
	dir, err := mirageDir()
	if err != nil {
		return "", err
	}
	return dir + "/history", nil
}

// tokenize splits a line into args, respecting single and double quoted strings.
func tokenize(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := rune(0)

	for _, r := range strings.TrimSpace(line) {
		switch {
		case inQuote != 0 && r == inQuote:
			inQuote = 0
		case inQuote != 0:
			current.WriteRune(r)
		case r == '\'' || r == '"':
			inQuote = r
		case unicode.IsSpace(r):
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// buildCompleter derives a tab-completion tree from the cobra command tree so
// it stays in sync automatically when commands are added or removed.
func buildCompleter() readline.AutoCompleter {
	items := cobraItems(newRootCmd())
	// Add REPL-only commands not present in the cobra tree.
	items = append(items,
		readline.PcItem("exit"),
		readline.PcItem("quit"),
	)
	return readline.NewPrefixCompleter(items...)
}

// cobraItems recursively converts a cobra command's subcommands into
// readline completion items.
func cobraItems(cmd *cobra.Command) []readline.PrefixCompleterInterface {
	var items []readline.PrefixCompleterInterface
	for _, sub := range cmd.Commands() {
		if sub.Hidden {
			continue
		}
		items = append(items, readline.PcItem(sub.Name(), cobraItems(sub)...))
	}
	return items
}
