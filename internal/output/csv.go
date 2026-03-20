package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// WriteCSV writes data as CSV. Accepts []map[string]interface{} or flattens structured data.
func WriteCSV(path string, data interface{}) error {
	rows, err := flattenToRows(data)
	if err != nil {
		return fmt.Errorf("flatten data for CSV: %w", err)
	}
	if len(rows) == 0 {
		return fmt.Errorf("no tabular data to export")
	}

	// Collect all unique keys across all rows for headers
	keySet := make(map[string]bool)
	for _, row := range rows {
		for k := range row {
			keySet[k] = true
		}
	}
	headers := make([]string, 0, len(keySet))
	for k := range keySet {
		headers = append(headers, k)
	}
	sort.Strings(headers)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header
	if err := w.Write(headers); err != nil {
		return err
	}

	// Write rows
	for _, row := range rows {
		record := make([]string, len(headers))
		for i, h := range headers {
			if v, ok := row[h]; ok {
				record[i] = fmt.Sprintf("%v", v)
			}
		}
		if err := w.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// flattenToRows converts various data shapes into []map[string]interface{}.
func flattenToRows(data interface{}) ([]map[string]interface{}, error) {
	// Marshal then unmarshal to get generic structure
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	// Try as array of objects first
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err == nil && len(arr) > 0 {
		return flattenNestedMaps(arr), nil
	}

	// Try as single object — look for array fields
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err == nil {
		for _, v := range obj {
			if arrVal, ok := v.([]interface{}); ok && len(arrVal) > 0 {
				var rows []map[string]interface{}
				for _, item := range arrVal {
					if m, ok := item.(map[string]interface{}); ok {
						rows = append(rows, m)
					}
				}
				if len(rows) > 0 {
					return flattenNestedMaps(rows), nil
				}
			}
		}
	}

	return nil, fmt.Errorf("data is not tabular")
}

// flattenNestedMaps flattens nested maps using dot notation.
func flattenNestedMaps(rows []map[string]interface{}) []map[string]interface{} {
	var flattened []map[string]interface{}
	for _, row := range rows {
		flat := make(map[string]interface{})
		flattenMap("", row, flat)
		flattened = append(flattened, flat)
	}
	return flattened
}

func flattenMap(prefix string, m map[string]interface{}, out map[string]interface{}) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		// Skip @odata fields
		if strings.HasPrefix(k, "@odata") {
			continue
		}
		switch val := v.(type) {
		case map[string]interface{}:
			flattenMap(key, val, out)
		case []interface{}:
			// Serialize arrays as comma-separated strings
			parts := make([]string, len(val))
			for i, item := range val {
				parts[i] = fmt.Sprintf("%v", item)
			}
			out[key] = strings.Join(parts, "; ")
		default:
			out[key] = v
		}
	}
}
