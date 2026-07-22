package main

import (
	"context"
	"fmt"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
)

// scanGCP lists VPC Firewall rules for the given project and returns every rule that is an ALLOW ingress rule with 0.0.0.0/0 (or ::/0) in its source
// ranges, for any protocol/port.
//
// Auth: uses Application Default Credentials. Run `gcloud auth application-default login`, or set GOOGLE_APPLICATION_CREDENTIALS
// to a service account key file, beforerunning this tool.
func scanGCP(ctx context.Context, projectID string) ([]GCPFirewallFinding, error) {
	client, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating GCP Firewalls client (check ADC credentials): %w", err)
	}
	defer client.Close()

	req := &computepb.ListFirewallsRequest{
		Project: projectID,
	}

	var findings []GCPFirewallFinding

	it := client.List(ctx, req)
	for {
		fw, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return findings, fmt.Errorf("listing GCP firewall rules: %w", err)
		}

		insecure := insecureGCPRules(fw)
		if len(insecure) == 0 {
			continue
		}

		findings = append(findings, GCPFirewallFinding{
			Name:          fw.GetName(),
			Network:       shortGCPNetworkName(fw.GetNetwork()),
			InsecureRules: insecure,
		})
	}

	return findings, nil
}

// insecureGCPRules flags ALLOW ingress rules on this firewall entry that include 0.0.0.0/0 or ::/0 in their source ranges.
func insecureGCPRules(fw *computepb.Firewall) []InsecureRule {
	// Only ingress rules have a meaningful "source" for our purposes;
	// egress rules use destinationRanges instead and are not "inbound from the internet" by definition.
	if fw.GetDirection() != "" && fw.GetDirection() != "INGRESS" {
		return nil
	}

	openSource := ""
	for _, r := range fw.GetSourceRanges() {
		if isInternetCIDR(r) {
			openSource = r
			break
		}
	}
	if openSource == "" {
		return nil
	}

	// A firewall entry with no Allowed rules but Denied rules is a DENY rule; only flag ALLOW entries as "insecure".
	if len(fw.GetAllowed()) == 0 {
		return nil
	}

	var out []InsecureRule
	for _, allowed := range fw.GetAllowed() {
		protocol := allowed.GetIPProtocol()
		ports := allowed.GetPorts()

		if len(ports) == 0 {
			out = append(out, InsecureRule{
				Protocol: protocol,
				Port:     "all",
				Source:   openSource,
			})
			continue
		}
		for _, p := range ports {
			out = append(out, InsecureRule{
				Protocol: protocol,
				Port:     p,
				Source:   openSource,
			})
		}
	}

	return out
}

// shortGCPNetworkName trims a full network resource URL down to just the network name (GCP returns something like
// "https://www.googleapis.com/compute/v1/projects/p/global/networks/default").
func shortGCPNetworkName(networkURL string) string {
	parts := strings.Split(networkURL, "/")
	if len(parts) == 0 {
		return networkURL
	}
	return parts[len(parts)-1]
}
