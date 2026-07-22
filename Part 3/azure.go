package main

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
)

// scanAzure lists Network Security Groups for the given subscription and returns every NSG that has at least one custom inbound "Allow" rule whose
// source is the internet (0.0.0.0/0, "*", "Internet", or "Any"), for any protocol/port.
//
// Auth: uses DefaultAzureCredential, which tries (in order) environment variables, managed identity, and `az login` credentials from the Azure
// CLI. Run `az login` before using this tool interactively.
func scanAzure(ctx context.Context, subscriptionID string) ([]AzureNSGFinding, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure credential: %w", err)
	}

	client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating Azure NSG client: %w", err)
	}

	var findings []AzureNSGFinding

	pager := client.NewListAllPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("listing Azure NSGs: %w", err)
		}

		for _, nsg := range page.Value {
			insecure := insecureAzureRules(nsg)
			if len(insecure) == 0 {
				continue
			}

			findings = append(findings, AzureNSGFinding{
				ID:            derefStr(nsg.ID),
				Name:          derefStr(nsg.Name),
				InsecureRules: insecure,
			})
		}
	}

	return findings, nil
}

// azureInternetSources are the values Azure accepts/returns that mean "any source address", i.e. the whole internet (and beyond, for "*"/"Any"
// which also cover the VNet/other Azure-internal ranges - we treat them as open-to-internet since they include 0.0.0.0/0).
func isAzureInternetSource(s string) bool {
	switch s {
	case "0.0.0.0/0", "*", "Internet", "Any":
		return true
	default:
		return false
	}
}

// insecureAzureRules flags custom inbound Allow rules on this NSG whose source address (or one of its source address prefixes) covers the internet.
func insecureAzureRules(nsg *armnetwork.SecurityGroup) []InsecureRule {
	if nsg.Properties == nil {
		return nil
	}

	var out []InsecureRule

	for _, rule := range nsg.Properties.SecurityRules {
		if rule.Properties == nil {
			continue
		}
		props := rule.Properties

		if props.Direction == nil || *props.Direction != armnetwork.SecurityRuleDirectionInbound {
			continue
		}
		if props.Access == nil || *props.Access != armnetwork.SecurityRuleAccessAllow {
			continue
		}

		openSource := ""
		if props.SourceAddressPrefix != nil && isAzureInternetSource(*props.SourceAddressPrefix) {
			openSource = *props.SourceAddressPrefix
		}
		if openSource == "" {
			for _, prefix := range props.SourceAddressPrefixes {
				if prefix != nil && isAzureInternetSource(*prefix) {
					openSource = *prefix
					break
				}
			}
		}
		if openSource == "" {
			continue
		}

		protocol := "*"
		if props.Protocol != nil {
			protocol = string(*props.Protocol)
		}

		ports := azurePortStrings(props)
		for _, port := range ports {
			out = append(out, InsecureRule{
				Protocol: protocol,
				Port:     port,
				Source:   openSource,
			})
		}
	}

	return out
}

// azurePortStrings collects the destination port range(s) for a rule.
func azurePortStrings(props *armnetwork.SecurityRulePropertiesFormat) []string {
	var ports []string

	if props.DestinationPortRange != nil {
		ports = append(ports, *props.DestinationPortRange)
	}
	for _, p := range props.DestinationPortRanges {
		if p != nil {
			ports = append(ports, *p)
		}
	}

	if len(ports) == 0 {
		return []string{"*"}
	}
	return ports
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
