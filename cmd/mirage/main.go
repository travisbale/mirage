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

	root.PersistentFlags().String("server", "", "server alias to use (default: client.json default)")
	root.PersistentFlags().Bool("json", false, "output raw JSON instead of formatted tables")

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(Version)
		},
	})

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
