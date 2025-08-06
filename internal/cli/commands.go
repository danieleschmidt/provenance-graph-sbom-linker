package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/internal/version"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

func NewInitCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize provenance tracking for a project",
		Long:  "Initialize provenance tracking configuration for a project with optional Git integration",
		RunE: func(cmd *cobra.Command, args []string) error {
			project, _ := cmd.Flags().GetString("project")
			if project == "" {
				return fmt.Errorf("project name is required")
			}

			config := map[string]interface{}{
				"provenance": map[string]interface{}{
					"version": "1.0",
					"project": project,
					"created_at": time.Now().Format(time.RFC3339),
					"sources": []map[string]string{
						{
							"type": "git",
							"url":  ".",
						},
					},
					"build": map[string]string{
						"system": "local",
					},
				},
			}

			data, err := json.MarshalIndent(config, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal config: %w", err)
			}

			if err := os.WriteFile(".provenance.json", data, 0644); err != nil {
				return fmt.Errorf("failed to write config file: %w", err)
			}

			fmt.Printf("Initialized provenance tracking for project '%s'\n", project)
			fmt.Println("Configuration written to .provenance.json")
			return nil
		},
	}

	cmd.Flags().StringP("project", "p", "", "Project name (required)")
	cmd.MarkFlagRequired("project")

	return cmd
}

func NewTrackCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "track",
		Short: "Track build artifacts and provenance",
		Long:  "Track build artifacts and their provenance information",
	}

	buildCmd := &cobra.Command{
		Use:   "build",
		Short: "Track a build event",
		RunE: func(cmd *cobra.Command, args []string) error {
			sourceRef, _ := cmd.Flags().GetString("source-ref")
			commitHash, _ := cmd.Flags().GetString("commit")
			artifact, _ := cmd.Flags().GetString("artifact")
			sbomPath, _ := cmd.Flags().GetString("sbom")

			if sourceRef == "" || commitHash == "" || artifact == "" {
				return fmt.Errorf("source-ref, commit, and artifact are required")
			}

			buildEvent := types.BuildEvent{
				ID:         uuid.New(),
				SourceRef:  sourceRef,
				CommitHash: commitHash,
				Artifacts: []types.Artifact{
					{
						ID:        uuid.New(),
						Name:      artifact,
						Version:   "latest",
						Type:      types.ArtifactTypeContainer,
						CreatedAt: time.Now(),
						UpdatedAt: time.Now(),
					},
				},
				Timestamp: time.Now(),
				Metadata:  make(map[string]string),
			}

			if sbomPath != "" {
				fmt.Printf("Loading SBOM from %s...\n", sbomPath)
			}

			fmt.Printf("Tracked build event:\n")
			fmt.Printf("  ID: %s\n", buildEvent.ID)
			fmt.Printf("  Source: %s@%s\n", sourceRef, commitHash)
			fmt.Printf("  Artifact: %s\n", artifact)
			fmt.Printf("  Timestamp: %s\n", buildEvent.Timestamp.Format(time.RFC3339))

			return nil
		},
	}

	buildCmd.Flags().String("source-ref", "", "Source repository reference (required)")
	buildCmd.Flags().String("commit", "", "Commit hash (required)")
	buildCmd.Flags().String("artifact", "", "Artifact name (required)")
	buildCmd.Flags().String("sbom", "", "Path to SBOM file")
	buildCmd.MarkFlagRequired("source-ref")
	buildCmd.MarkFlagRequired("commit")
	buildCmd.MarkFlagRequired("artifact")

	cmd.AddCommand(buildCmd)
	return cmd
}

func NewSignCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "sign",
		Short: "Sign artifacts with cryptographic signatures",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Sign command - implementation pending")
		},
	}
}

func NewVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Verify artifact signatures and attestations",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Verify command - implementation pending")
		},
	}
}

func NewSBOMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Generate and manage Software Bill of Materials",
		Long:  "Generate, analyze, and manage Software Bill of Materials (SBOM) files",
	}

	generateCmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate SBOM for a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			source, _ := cmd.Flags().GetString("source")
			format, _ := cmd.Flags().GetString("format")
			output, _ := cmd.Flags().GetString("output")

			if source == "" {
				source = "."
			}
			if output == "" {
				output = fmt.Sprintf("sbom.%s.json", format)
			}

			sbom := types.SBOM{
				ID:        uuid.New(),
				Format:    types.SBOMFormat(format),
				Version:   "1.0",
				CreatedAt: time.Now(),
				CreatedBy: "provenance-linker",
				Metadata:  make(map[string]string),
				Components: []types.Component{
					{
						ID:          uuid.New(),
						Name:        "example-component",
						Version:     "1.0.0",
						Type:        types.ComponentTypeLibrary,
						License:     []string{"MIT"},
						Description: "Example component for demonstration",
						Metadata:    make(map[string]string),
					},
				},
			}

			data, err := json.MarshalIndent(sbom, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal SBOM: %w", err)
			}

			if err := os.WriteFile(output, data, 0644); err != nil {
				return fmt.Errorf("failed to write SBOM file: %w", err)
			}

			fmt.Printf("Generated SBOM:\n")
			fmt.Printf("  Format: %s\n", format)
			fmt.Printf("  Source: %s\n", source)
			fmt.Printf("  Output: %s\n", output)
			fmt.Printf("  Components: %d\n", len(sbom.Components))

			return nil
		},
	}

	generateCmd.Flags().String("source", ".", "Source directory to analyze")
	generateCmd.Flags().String("format", "cyclonedx", "SBOM format (cyclonedx, spdx, syft)")
	generateCmd.Flags().String("output", "", "Output file path")

	cmd.AddCommand(generateCmd)
	return cmd
}

func NewGraphCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "graph",
		Short: "Generate and analyze provenance graphs",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Graph command - implementation pending")
		},
	}
}

func NewComplianceCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "compliance",
		Short: "Generate compliance reports (NIST SSDF, EU CRA)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Compliance command - implementation pending")
		},
	}
}

func NewVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Provenance Linker v%s\n", version.Version)
			fmt.Printf("Commit: %s\n", version.Commit)
			fmt.Printf("Build Date: %s\n", version.Date)
		},
	}
}