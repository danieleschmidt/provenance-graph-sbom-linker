package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/sbom"
	"github.com/danieleschmidt/provenance-graph-sbom-linker/pkg/types"
)

// ProvenanceNode represents a node in the provenance graph
type ProvenanceNode struct {
	ID          string            `json:"id"`
	BomRef      string            `json:"bom_ref,omitempty"`
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Type        string            `json:"type"`
	Hash        string            `json:"hash,omitempty"` // Original component hash (from SBOM)
	Attestation string            `json:"attestation"`    // SHA-256 of component data
	ChainHash   string            `json:"chain_hash"`     // SHA-256 chained with predecessor
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ProvenanceEdge represents a dependency relationship
type ProvenanceEdge struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Relation string `json:"relation"`
}

// ProvenanceGraph is the complete provenance graph with attestation chain
type ProvenanceGraph struct {
	SBOMID      string            `json:"sbom_id"`
	Format      string            `json:"format"`
	GeneratedAt string            `json:"generated_at"`
	NodeCount   int               `json:"node_count"`
	EdgeCount   int               `json:"edge_count"`
	Nodes       []*ProvenanceNode `json:"nodes"`
	Edges       []*ProvenanceEdge `json:"edges"`
	RootHash    string            `json:"root_hash"` // Merkle-style chain root
}

// rawCycloneDXDependencies extracts bom-ref dependency graph from raw JSON
type rawCycloneDX struct {
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
}

// buildProvenanceGraph constructs a provenance graph from a parsed SBOM + raw dep data
func buildProvenanceGraph(s *types.SBOM, depMap map[string][]string) *ProvenanceGraph {
	graph := &ProvenanceGraph{
		SBOMID:      s.ID.String(),
		Format:      string(s.Format),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Index components by bom-ref for edge building
	nodeByBomRef := make(map[string]*ProvenanceNode)
	prevHash := "" // chain seed

	for _, comp := range s.Components {
		bomRef := ""
		if comp.Metadata != nil {
			bomRef = comp.Metadata["bom-ref"]
		}

		// Build attestation: SHA-256 of (name + version + type + hash)
		// This creates a unique, verifiable fingerprint for each component
		attestInput := fmt.Sprintf("%s|%s|%s|%s", comp.Name, comp.Version, string(comp.Type), comp.Hash)
		attestBytes := sha256.Sum256([]byte(attestInput))
		attestation := hex.EncodeToString(attestBytes[:])

		// Build chain hash: SHA-256 of (attestation + prevHash)
		// This creates a tamper-evident chain — any modification breaks the chain
		chainInput := attestation + prevHash
		chainBytes := sha256.Sum256([]byte(chainInput))
		chainHash := hex.EncodeToString(chainBytes[:])

		// Only expose non-internal metadata
		meta := make(map[string]string)
		if comp.Metadata != nil {
			if purl := comp.Metadata["purl"]; purl != "" {
				meta["purl"] = purl
			}
		}
		if len(comp.License) > 0 {
			meta["license"] = strings.Join(comp.License, ", ")
		}
		if comp.Description != "" {
			meta["description"] = comp.Description
		}

		node := &ProvenanceNode{
			ID:          comp.ID.String(),
			BomRef:      bomRef,
			Name:        comp.Name,
			Version:     comp.Version,
			Type:        string(comp.Type),
			Hash:        comp.Hash,
			Attestation: attestation,
			ChainHash:   chainHash,
			Metadata:    meta,
		}

		graph.Nodes = append(graph.Nodes, node)
		if bomRef != "" {
			nodeByBomRef[bomRef] = node
		}
		prevHash = chainHash
	}

	// Build edges from CycloneDX dependency declarations
	for fromRef, toRefs := range depMap {
		fromNode, fromExists := nodeByBomRef[fromRef]
		if !fromExists {
			continue
		}
		for _, toRef := range toRefs {
			toNode, toExists := nodeByBomRef[toRef]
			if !toExists {
				continue
			}
			graph.Edges = append(graph.Edges, &ProvenanceEdge{
				From:     fromNode.ID,
				To:       toNode.ID,
				Relation: "depends_on",
			})
		}
	}

	// Compute root hash (SHA-256 of all chain hashes concatenated in order)
	// This gives a single fingerprint for the entire provenance graph
	if len(graph.Nodes) > 0 {
		var chainCombined strings.Builder
		for _, n := range graph.Nodes {
			chainCombined.WriteString(n.ChainHash)
		}
		rootBytes := sha256.Sum256([]byte(chainCombined.String()))
		graph.RootHash = hex.EncodeToString(rootBytes[:])
	}

	graph.NodeCount = len(graph.Nodes)
	graph.EdgeCount = len(graph.Edges)

	return graph
}

func main() {
	sbomFile := "sample-cyclonedx.json"
	if len(os.Args) > 1 {
		sbomFile = os.Args[1]
	}

	fmt.Printf("╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║     Provenance Graph SBOM Linker — Dissertation Demo         ║\n")
	fmt.Printf("║     Supply Chain Security via Cryptographic Attestation      ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n\n")

	// Read SBOM file
	fmt.Printf("📦 Loading SBOM: %s\n", sbomFile)
	data, err := os.ReadFile(sbomFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading SBOM file: %v\n", err)
		os.Exit(1)
	}

	// Detect and parse SBOM format
	parser := sbom.NewParser()
	format, err := parser.DetectFormat(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error detecting SBOM format: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Detected format: %s\n\n", format)

	parsed, err := parser.ParseCycloneDX(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing SBOM: %v\n", err)
		os.Exit(1)
	}

	// Extract dependency graph from raw JSON (the parser doesn't pass this through yet)
	var rawDeps rawCycloneDX
	_ = json.Unmarshal(data, &rawDeps) // best effort
	depMap := make(map[string][]string)
	for _, dep := range rawDeps.Dependencies {
		depMap[dep.Ref] = dep.DependsOn
	}

	fmt.Printf("📊 SBOM Summary:\n")
	fmt.Printf("   ID:           %s\n", parsed.ID)
	fmt.Printf("   Format:       %s (v%s)\n", parsed.Format, parsed.Version)
	fmt.Printf("   Components:   %d\n", len(parsed.Components))
	fmt.Printf("   Dep entries:  %d\n", len(rawDeps.Dependencies))
	fmt.Printf("   Created:      %s\n\n", parsed.CreatedAt.Format(time.RFC3339))

	// Build provenance graph with cryptographic attestation
	fmt.Printf("🔗 Building Provenance Graph with Cryptographic Attestation...\n\n")
	graph := buildProvenanceGraph(parsed, depMap)

	fmt.Printf("┌─────────────────────────────────────────────────────────────┐\n")
	fmt.Printf("│ PROVENANCE GRAPH: %d nodes (components), %d edges (deps)%s\n",
		graph.NodeCount, graph.EdgeCount,
		strings.Repeat(" ", max(0, 14-len(fmt.Sprintf("%d", graph.NodeCount))-len(fmt.Sprintf("%d", graph.EdgeCount)))))
	fmt.Printf("└─────────────────────────────────────────────────────────────┘\n\n")

	// Display nodes with attestation
	fmt.Printf("🔐 Component Attestations (SHA-256 cryptographic chain):\n\n")
	for i, node := range graph.Nodes {
		shortAttest := node.Attestation
		if len(shortAttest) > 16 {
			shortAttest = shortAttest[:16] + "..."
		}
		shortChain := node.ChainHash
		if len(shortChain) > 16 {
			shortChain = shortChain[:16] + "..."
		}

		fmt.Printf("  [%d] %s@%s (%s)\n", i+1, node.Name, node.Version, node.Type)
		if node.Hash != "" {
			fmt.Printf("      Original Hash:  %.32s...\n", node.Hash)
		}
		fmt.Printf("      Attestation:    %s\n", shortAttest)
		fmt.Printf("      Chain Hash:     %s\n", shortChain)
		if purl := node.Metadata["purl"]; purl != "" {
			fmt.Printf("      PURL:           %s\n", purl)
		}
		if lic := node.Metadata["license"]; lic != "" {
			fmt.Printf("      License:        %s\n", lic)
		}
		fmt.Println()
	}

	fmt.Printf("🌳 Root Hash (tamper-evident fingerprint of entire graph):\n")
	fmt.Printf("   %s\n\n", graph.RootHash)

	if graph.EdgeCount > 0 {
		fmt.Printf("↔️  Dependency Edges (%d total):\n", graph.EdgeCount)
		// Find node names by ID for display
		nodeNames := make(map[string]string)
		for _, n := range graph.Nodes {
			nodeNames[n.ID] = fmt.Sprintf("%s@%s", n.Name, n.Version)
		}
		for _, edge := range graph.Edges {
			from := nodeNames[edge.From]
			to := nodeNames[edge.To]
			if from == "" {
				from = edge.From[:8] + "..."
			}
			if to == "" {
				to = edge.To[:8] + "..."
			}
			fmt.Printf("   %-40s → %s\n", from, to)
		}
		fmt.Println()
	}

	// Output full graph as JSON
	outFile := "demo-provenance-graph.json"
	jsonData, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling graph: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(outFile, jsonData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Provenance graph written to: %s\n", outFile)
	fmt.Printf("\n🎓 Dissertation relevance — this demonstrates:\n")
	fmt.Printf("   1. ✅ SBOM parsing      — CycloneDX JSON format with %d components\n", graph.NodeCount)
	fmt.Printf("   2. ✅ Graph construction — nodes=components, edges=%d dependency relationships\n", graph.EdgeCount)
	fmt.Printf("   3. ✅ Cryptographic attestation — SHA-256 per component (name+version+type+hash)\n")
	fmt.Printf("   4. ✅ Tamper-evident chain — each hash includes predecessor hash\n")
	fmt.Printf("   5. ✅ Root hash integrity — single fingerprint covers entire graph\n")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
