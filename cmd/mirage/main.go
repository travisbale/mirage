package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var Version = "dev"

func main() {
	root := &cobra.Command{
		Use:          "mirage",
		Short:        "Mirage CLI — manage miraged instances",
		SilenceUsage: true,
	}

	root.PersistentFlags().String("server", "", "server alias (default: client.json default_server)")
	root.PersistentFlags().Bool("json", false, "output raw JSON instead of formatted tables")
	root.PersistentFlags().String("config", "", "path to client.json (default: ~/.mirage/client.json)")

	root.AddCommand(
		newServerCmd(),
		newSessionsCmd(),
		newLuresCmd(),
		newPhishletsCmd(),
		newBlacklistCmd(),
		newBotguardCmd(),
		&cobra.Command{
			Use:   "version",
			Short: "Print the version and exit",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Println(Version)
			},
		},
	)

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
