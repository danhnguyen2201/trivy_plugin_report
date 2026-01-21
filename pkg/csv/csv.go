package csv

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
)

// sanitize prevents CSV Injection (Formula Injection).
func sanitize(s string) string {
	if len(s) > 0 && (strings.HasPrefix(s, "=") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@")) {
		return "'" + s
	}
	return s
}

// Export writes the Trivy scan report to a CSV file at the specified path.
func Export(report *types.Report, path string) error {
	// 1. Create the output file
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// 2. Initialize the CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 3. Write the CSV Header
	header := []string{
		"Target", "Type", "Vulnerability ID", "Severity",
		"Pkg Name", "Installed Version", "Fixed Version",
		"Title", "Primary URL",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// 4. Iterate through results and write data rows
	for _, result := range report.Results {
		// Skip results with no vulnerabilities
		if len(result.Vulnerabilities) == 0 {
			continue
		}

		for _, vuln := range result.Vulnerabilities {
			// Handle missing fixed version
			fixedVer := vuln.FixedVersion
			if fixedVer == "" {
				fixedVer = "-"
			}

			// Get the primary URL (if available)
			primaryURL := ""
			if len(vuln.References) > 0 {
				primaryURL = vuln.References[0]
			}

			// Apply sanitization to all fields to prevent injection attacks
			row := []string{
				sanitize(result.Target),
				sanitize(string(result.Class)),
				sanitize(vuln.VulnerabilityID),
				sanitize(vuln.Severity),
				sanitize(vuln.PkgName),
				sanitize(vuln.InstalledVersion),
				sanitize(fixedVer),
				sanitize(vuln.Title),
				sanitize(primaryURL),
			}

			if err := writer.Write(row); err != nil {
				return fmt.Errorf("error writing record for %s: %w", vuln.VulnerabilityID, err)
			}
		}
	}

	return nil
}