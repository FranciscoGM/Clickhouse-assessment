package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

// ---- Output schema -------------------------------------------------------

// InsecureRule describes a single inbound rule that is open to the internet.
type InsecureRule struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"` // string so we can represent "all"/"*" as well as numeric ports
	Source   string `json:"source"`
}

// AWSSecurityGroupFinding is one AWS security group with its offending rules.
type AWSSecurityGroupFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// GCPFirewallFinding is one GCP firewall rule with its offending rules.
type GCPFirewallFinding struct {
	Name          string         `json:"name"`
	Network       string         `json:"network"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// AzureNSGFinding is one Azure NSG with its offending rules.
type AzureNSGFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

// Report is the top-level JSON document produced by the tool.
type Report struct {
	AWS struct {
		SecurityGroups []AWSSecurityGroupFinding `json:"security_groups"`
	} `json:"aws"`
	GCP struct {
		FirewallRules []GCPFirewallFinding `json:"firewall_rules"`
	} `json:"gcp"`
	Azure struct {
		NSGs []AzureNSGFinding `json:"nsgs"`
	} `json:"azure"`

	// Scan metadata / non-fatal errors, kept out of the main provider blocks so the example schema in the spec stays intact.
	Errors    []string `json:"errors,omitempty"`
	ScannedAt string   `json:"scanned_at"`
}

// ---- Provider interface ---------------------------------------------------

func main() {
	var (
		awsProfile  = flag.String("aws-profile", "", "AWS named profile to use (optional; defaults to standard AWS credential chain)")
		awsRegions  = flag.String("aws-regions", "", "Comma-separated AWS regions to scan (optional; defaults to the region in your AWS config)")
		gcpProject  = flag.String("gcp-project", "", "GCP project ID to scan (required to enable the GCP scan)")
		azureSubID  = flag.String("azure-subscription", "", "Azure subscription ID to scan (required to enable the Azure scan)")
		skipAWS     = flag.Bool("skip-aws", false, "Skip the AWS scan")
		skipGCP     = flag.Bool("skip-gcp", false, "Skip the GCP scan")
		skipAzure   = flag.Bool("skip-azure", false, "Skip the Azure scan")
		timeoutFlag = flag.Duration("timeout", 2*time.Minute, "Overall timeout for the scan")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	report := Report{ScannedAt: time.Now().UTC().Format(time.RFC3339)}
	report.AWS.SecurityGroups = []AWSSecurityGroupFinding{}
	report.GCP.FirewallRules = []GCPFirewallFinding{}
	report.Azure.NSGs = []AzureNSGFinding{}

	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)

	addErr := func(msg string) {
		mu.Lock()
		report.Errors = append(report.Errors, msg)
		mu.Unlock()
	}

	if !*skipAWS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var regions []string
			if *awsRegions != "" {
				regions = splitAndTrim(*awsRegions)
			}
			findings, err := scanAWS(ctx, *awsProfile, regions)
			if err != nil {
				addErr(fmt.Sprintf("aws: %v", err))
				return
			}
			mu.Lock()
			report.AWS.SecurityGroups = findings
			mu.Unlock()
		}()
	}

	if !*skipGCP {
		if *gcpProject == "" {
			addErr("gcp: skipped, --gcp-project not set")
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, err := scanGCP(ctx, *gcpProject)
				if err != nil {
					addErr(fmt.Sprintf("gcp: %v", err))
					return
				}
				mu.Lock()
				report.GCP.FirewallRules = findings
				mu.Unlock()
			}()
		}
	}

	if !*skipAzure {
		if *azureSubID == "" {
			addErr("azure: skipped, --azure-subscription not set")
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				findings, err := scanAzure(ctx, *azureSubID)
				if err != nil {
					addErr(fmt.Sprintf("azure: %v", err))
					return
				}
				mu.Lock()
				report.Azure.NSGs = findings
				mu.Unlock()
			}()
		}
	}

	wg.Wait()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "failed to encode report: %v\n", err)
		os.Exit(1)
	}

	// Non-zero exit if any insecure rule was found, so this can be used as a CI gate; scan errors alone don't affect this exit code.
	if reportHasFindings(report) {
		os.Exit(2)
	}
}

func reportHasFindings(r Report) bool {
	for _, sg := range r.AWS.SecurityGroups {
		if len(sg.InsecureRules) > 0 {
			return true
		}
	}
	for _, fw := range r.GCP.FirewallRules {
		if len(fw.InsecureRules) > 0 {
			return true
		}
	}
	for _, nsg := range r.Azure.NSGs {
		if len(nsg.InsecureRules) > 0 {
			return true
		}
	}
	return false
}

func splitAndTrim(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := s[start:i]
			// trim spaces
			for len(part) > 0 && part[0] == ' ' {
				part = part[1:]
			}
			for len(part) > 0 && part[len(part)-1] == ' ' {
				part = part[:len(part)-1]
			}
			if part != "" {
				out = append(out, part)
			}
			start = i + 1
		}
	}
	return out
}

// isInternetCIDR reports whether a CIDR/source string represents "the entire internet" for IPv4 or IPv6.
func isInternetCIDR(s string) bool {
	switch s {
	case "0.0.0.0/0", "::/0":
		return true
	default:
		return false
	}
}
