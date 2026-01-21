package excel

import (
	"fmt"
	"strings"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/xuri/excelize/v2"
)

const (
	VulnReport = "Vulnerability Scan Report"
)

var (
	// Mapping Class to English description
	ResultClass = map[types.ResultClass]string{
		types.ClassOSPkg:   "OS Packages",
		types.ClassLangPkg: "Language Packages",
	}

	// Severity Colors (Hex codes)
	SeverityColor = map[string]string{
		"CRITICAL": "FF7675", // Deep Red
		"HIGH":     "FAB1A0", // Light Red/Orange
		"MEDIUM":   "FFEAA7", // Yellow
		"LOW":      "74B9FF", // Light Blue
		"UNKNOWN":  "DFE6E9", // Grey
	}

	VulnHeaderValues = []string{
		"Target", "Type", "Class", "Vulnerability ID", "Title",
		"Severity Source", "Severity", "Package Name", "Installed Version", "Path",
		"Fixed Version", "Status",
	}

	VulnHeaderWidths = map[string]float64{
		"A": 25, "B": 15, "C": 15, "D": 20, "E": 40,
		"F": 15, "G": 12, "H": 20, "I": 20, "J": 30,
		"K": 20, "L": 15,
	}
)

// sanitize prevents Excel Formula Injection (SECURITY)
// It escapes strings starting with =, +, -, @ by adding a single quote prefix.
func sanitize(s string) string {
	if len(s) > 0 && (strings.HasPrefix(s, "=") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "@")) {
		return "'" + s
	}
	return s
}

// Export generates an Excel report from the Trivy scan results.
func Export(report *types.Report, fileName string, beautify bool) error {
	f := excelize.NewFile()
	
	// 1. Initialize Sheet and Header
	// Create the vulnerability report sheet
	index, err := f.NewSheet(VulnReport)
	if err != nil {
		return fmt.Errorf("failed to create sheet: %w", err)
	}
	f.SetActiveSheet(index)
	f.DeleteSheet("Sheet1") // Remove the default empty sheet

	// Create Headers
	if err := createVulnHeaders(f); err != nil {
		return err
	}

	rowNum := 2
	hasVuln := false

	// 2. Define Default Style
	// Basic style with borders and text wrapping
	defaultStyleID, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{WrapText: true, Vertical: "top", Horizontal: "left"},
		Border: []excelize.Border{
			{Type: "left", Style: 1, Color: "000000"},
			{Type: "top", Style: 1, Color: "000000"},
			{Type: "right", Style: 1, Color: "000000"},
			{Type: "bottom", Style: 1, Color: "000000"},
		},
	})

	// 3. Iterate over results
	for _, result := range report.Results {
		if len(result.Vulnerabilities) == 0 {
			continue
		}
		hasVuln = true

		for _, vuln := range result.Vulnerabilities {
			// Parse vulnerability data (sanitization is applied within parseVulnData)
			data := parseVulnData(result.Target, result.Type, result.Class, vuln)
			
			cell, _ := excelize.CoordinatesToCellName(1, rowNum)
			if err := f.SetSheetRow(VulnReport, cell, &data); err != nil {
				return fmt.Errorf("failed to add row %d: %w", rowNum, err)
			}

			// Apply Row Style (Border + Optional Coloring)
			startCell := fmt.Sprintf("A%d", rowNum)
			endCell := fmt.Sprintf("L%d", rowNum)

			if beautify {
				// If beautify is enabled, apply color based on severity
				if color, ok := SeverityColor[vuln.Severity]; ok {
					styleID, _ := f.NewStyle(&excelize.Style{
						Alignment: &excelize.Alignment{WrapText: true, Vertical: "top", Horizontal: "left"},
						Border: []excelize.Border{
							{Type: "left", Style: 1, Color: "000000"},
							{Type: "top", Style: 1, Color: "000000"},
							{Type: "right", Style: 1, Color: "000000"},
							{Type: "bottom", Style: 1, Color: "000000"},
						},
						Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{color}},
					})
					f.SetCellStyle(VulnReport, startCell, endCell, styleID)
				} else {
					// Fallback to default style if color is not defined
					f.SetCellStyle(VulnReport, startCell, endCell, defaultStyleID)
				}
			} else {
				// If beautify is disabled, apply borders only
				f.SetCellStyle(VulnReport, startCell, endCell, defaultStyleID)
			}

			rowNum++
		}
	}

	// Save the file even if no vulnerabilities are found (empty report with headers)
	if hasVuln {
		return f.SaveAs(fileName)
	}
	
	return f.SaveAs(fileName)
}

// createVulnHeaders sets up the header row with styles and column widths.
func createVulnHeaders(f *excelize.File) error {
	// Set Header Values
	if err := f.SetSheetRow(VulnReport, "A1", &VulnHeaderValues); err != nil {
		return err
	}

	// Define Header Style (Bold, Dark Gray Background, White Text)
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#4F4F4F"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})
	f.SetCellStyle(VulnReport, "A1", "L1", headerStyle)

	// Set Column Widths
	for col, width := range VulnHeaderWidths {
		f.SetColWidth(VulnReport, col, col, width)
	}
	return nil
}

// parseVulnData prepares a row of data for the Excel sheet.
// It converts types and sanitizes inputs to prevent injection attacks.
func parseVulnData(target string, rType ftypes.TargetType, rClass types.ResultClass, vuln types.DetectedVulnerability) []interface{} {
	classStr := string(rClass)
	if v, ok := ResultClass[rClass]; ok {
		classStr = v
	}

	// Safely convert status to string (handling potential enum types)
	statusStr := fmt.Sprint(vuln.Status)

	// IMPORTANT: Wrap all string fields with sanitize() to prevent CSV/Excel Injection.
	// Returning []interface{} ensures better compatibility with excelize's SetSheetRow.
	return []interface{}{
		sanitize(target),
		sanitize(string(rType)),
		sanitize(classStr),
		sanitize(vuln.VulnerabilityID),
		sanitize(vuln.Title),
		sanitize(string(vuln.SeveritySource)),
		sanitize(vuln.Severity),
		sanitize(vuln.PkgName),
		sanitize(vuln.InstalledVersion),
		sanitize(vuln.PkgPath),
		sanitize(vuln.FixedVersion),
		sanitize(statusStr),
	}
}