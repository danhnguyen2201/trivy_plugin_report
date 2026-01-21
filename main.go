package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/spf13/cobra"
	"trivy-plugin-excel/pkg/csv"
	"trivy-plugin-excel/pkg/excel"
	"trivy-plugin-excel/pkg/pdf"
)

// main is the entry point for the Trivy report exporter plugin.
func main() {
	var output string
	var beautify bool

	var rootCmd = &cobra.Command{
		Use:   "report",
		Short: "Export Trivy results to Excel, PDF, and CSV",
		Long:  "A Trivy plugin that reads JSON reports from stdin and exports them to specified formats (.xlsx, .pdf, .csv).",
		Run: func(cmd *cobra.Command, args []string) {
			var report types.Report

			// Decode the JSON report from standard input (stdin)
			if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
				log.Fatal("Error reading JSON input: %v", err)
			}

			// Parse the output filename to determine the extension and base name
			// Normalize extension to lowercase for consistent comparison
			ext := strings.ToLower(filepath.Ext(output))
			baseName := strings.TrimSuffix(output, filepath.Ext(output))

			if baseName == "" {
				baseName = "report"
			}

			// Determine which formats to export based on the file extension
			var exportExcel, exportPdf, exportCsv bool

			switch ext {
			case ".xlsx":
				exportExcel = true
			case ".pdf":
				exportPdf = true
			case ".csv":
				exportCsv = true
			case "":
				// If no extension is provided, export to all supported formats by default
				exportExcel = true
				exportPdf = true
				exportCsv = true
			default:
				log.Fatal("Unsupported file extension: %s. Supported formats are .xlsx, .pdf, or .csv", ext)
			}

			log.Infof("Generating reports for base name: %s", baseName)

			// Use a WaitGroup to handle concurrent export operations
			var wg sync.WaitGroup

			// Goroutine 1: Export to Excel
			if exportExcel {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".xlsx"
					if err := excel.Export(&report, fileName, beautify); err != nil {
						log.Errorf("Failed to export Excel: %v", err)
					} else {
						log.Infof("Successfully created: %s", fileName)
					}
				}()
			}

			// Goroutine 2: Export to PDF
			if exportPdf {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".pdf"
					if err := pdf.Export(&report, fileName); err != nil {
						log.Errorf("Failed to export PDF: %v", err)
					} else {
						log.Infof("Successfully created: %s", fileName)
					}
				}()
			}

			// Goroutine 3: Export to CSV
			if exportCsv {
				wg.Add(1)
				go func() {
					defer wg.Done()
					fileName := baseName + ".csv"
					// CSV format does not support 'beautify' option
					if err := csv.Export(&report, fileName); err != nil {
						log.Errorf("Failed to export CSV: %v", err)
					} else {
						log.Infof("Successfully created: %s", fileName)
					}
				}()
			}

			// Wait for all export routines to finish
			wg.Wait()
			log.Infof("All reports generated successfully!")
		},
	}

	// Define command-line flags
	rootCmd.Flags().StringVarP(&output, "output", "o", "report", "Output filename (e.g., report.xlsx, report.pdf, or just 'report')")
	rootCmd.Flags().BoolVarP(&beautify, "beautify", "b", true, "Enable color formatting (Excel only)")

	// Execute the root command
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}