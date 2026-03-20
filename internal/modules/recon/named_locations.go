package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/graphrunner/internal/graph"
	"github.com/graphrunner/internal/output"
)

// NamedLocation represents a Conditional Access named location.
type NamedLocation struct {
	ODataType          string          `json:"@odata.type"`
	ID                 string          `json:"id"`
	DisplayName        string          `json:"displayName"`
	CreatedDateTime    string          `json:"createdDateTime"`
	ModifiedDateTime   string          `json:"modifiedDateTime"`
	IsTrusted          bool            `json:"isTrusted"`
	IPRanges           json.RawMessage `json:"ipRanges,omitempty"`
	CountriesAndRegions []string       `json:"countriesAndRegions,omitempty"`
	IncludeUnknown     bool            `json:"includeUnknownCountriesAndRegions,omitempty"`
}

// NamedLocationsResult holds all named locations from Conditional Access.
type NamedLocationsResult struct {
	Locations []NamedLocation `json:"locations"`
	IPBased   int             `json:"ip_based_count"`
	Country   int             `json:"country_based_count"`
	Trusted   int             `json:"trusted_count"`
	Total     int             `json:"total"`
}

// NamedLocations enumerates Conditional Access named locations (trusted IPs/networks/countries).
// Requires Policy.Read.All or ConditionalAccess.Read.
func NamedLocations(ctx context.Context, c *graph.Client) (*NamedLocationsResult, error) {
	output.Info("Fetching named locations (trusted IPs/countries)...")

	raw, err := c.GetAll(ctx, "/identity/conditionalAccess/namedLocations", nil)
	if err != nil {
		return nil, err
	}

	result := &NamedLocationsResult{}
	for _, r := range raw {
		var loc NamedLocation
		if err := json.Unmarshal(r, &loc); err != nil {
			continue
		}
		result.Locations = append(result.Locations, loc)

		switch loc.ODataType {
		case "#microsoft.graph.ipNamedLocation":
			result.IPBased++
			if loc.IsTrusted {
				result.Trusted++
			}
			output.Verbose("[named-location] IP: %s (trusted: %v)", loc.DisplayName, loc.IsTrusted)
		case "#microsoft.graph.countryNamedLocation":
			result.Country++
			output.Verbose("[named-location] Country: %s — %v", loc.DisplayName, loc.CountriesAndRegions)
		default:
			output.Verbose("[named-location] %s: %s", loc.ODataType, loc.DisplayName)
		}
	}
	result.Total = len(result.Locations)

	printNamedLocationsResults(result)
	return result, nil
}

func printNamedLocationsResults(result *NamedLocationsResult) {
	subtitle := fmt.Sprintf("%d IP-based, %d country-based, %d trusted",
		result.IPBased, result.Country, result.Trusted)
	output.SearchResultHeader("Named Locations (Conditional Access)", result.Total, subtitle)

	if result.Total == 0 {
		output.Warn("No named locations configured")
		return
	}

	// IP-based locations
	var ipLocs []NamedLocation
	var countryLocs []NamedLocation
	for _, loc := range result.Locations {
		if loc.ODataType == "#microsoft.graph.ipNamedLocation" {
			ipLocs = append(ipLocs, loc)
		} else if loc.ODataType == "#microsoft.graph.countryNamedLocation" {
			countryLocs = append(countryLocs, loc)
		}
	}

	untrusted := 0

	if len(ipLocs) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" IP-Based Locations (%d) ", len(ipLocs))))
		for i, loc := range ipLocs {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(loc.DisplayName)

			trustedTag := output.StyleSuccess.Render("[Trusted]")
			if !loc.IsTrusted {
				trustedTag = output.StyleHigh.Render("[Untrusted]")
				untrusted++
			}

			fmt.Printf("  %s %s  %s\n", num, nameStyled, trustedTag)

			// Parse IP ranges from JSON
			if len(loc.IPRanges) > 0 && string(loc.IPRanges) != "null" {
				var ranges []map[string]interface{}
				if err := json.Unmarshal(loc.IPRanges, &ranges); err == nil {
					for _, r := range ranges {
						cidr, _ := r["cidrAddress"].(string)
						if cidr != "" {
							fmt.Printf("       %s %s\n",
								output.StyleDim.Render("»"),
								output.StyleURLInfo.Render(cidr))
						}
					}
				}
			}

			if loc.ModifiedDateTime != "" {
				ts := loc.ModifiedDateTime
				if len(ts) > 10 {
					ts = ts[:10]
				}
				fmt.Printf("       %s\n", output.StyleDim.Render("Modified: "+ts))
			}
			fmt.Println()
		}
	}

	// Country-based locations
	if len(countryLocs) > 0 {
		fmt.Printf("  %s\n\n", output.StyleTableHeader.Render(fmt.Sprintf(" Country-Based Locations (%d) ", len(countryLocs))))
		for i, loc := range countryLocs {
			num := output.StyleCounter.Render(fmt.Sprintf(" %-3d", i+1))
			nameStyled := output.StyleBold.Render(loc.DisplayName)

			countries := strings.Join(loc.CountriesAndRegions, ", ")
			if len(countries) > 80 {
				countries = countries[:77] + "..."
			}

			fmt.Printf("  %s %s\n", num, nameStyled)
			if countries != "" {
				fmt.Printf("       %s %s\n",
					output.StyleDim.Render("Countries:"),
					output.StyleURLInfo.Render(countries))
			}
			if loc.IncludeUnknown {
				fmt.Printf("       %s\n", output.StyleMedium.Render("[Includes unknown countries]"))
			}
			fmt.Println()
		}
	}

	output.SearchDivider()

	if untrusted > 0 {
		output.Warn("%d IP-based location(s) are NOT marked as trusted", untrusted)
	}

	fmt.Println()
	output.Success("Named locations: %d total | %d IP-based | %d country-based | %d trusted",
		result.Total, result.IPBased, result.Country, result.Trusted)
}
