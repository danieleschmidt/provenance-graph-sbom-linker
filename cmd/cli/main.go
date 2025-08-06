package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/cli"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "provenance-linker",
		Short: "Provenance Graph SBOM Linker CLI",
		Long:  "End-to-end software supply chain provenance tracker with cryptographic attestation",
		Version: fmt.Sprintf("%s (commit: %s, date: %s)", 
			version.Version, version.Commit, version.Date),
	}

	rootCmd.AddCommand(
		cli.NewInitCommand(),
		cli.NewTrackCommand(),
		cli.NewSignCommand(),
		cli.NewVerifyCommand(),
		cli.NewSBOMCommand(),
		cli.NewGraphCommand(),
		cli.NewComplianceCommand(),
		cli.NewVersionCommand(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}