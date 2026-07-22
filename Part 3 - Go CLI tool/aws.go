package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// scanAWS lists EC2 Security Groups across the given regions (or the caller's default region if none are given) and returns every group that
// has at least one inbound rule open to 0.0.0.0/0 or ::/0, along with just the offending rules.
//
// Auth: uses the standard AWS SDK default credential chain (env vars, shared credentials/config files, SSO, EC2/ECS instance role, etc.).
// Pass --aws-profile to select a named profile.
func scanAWS(ctx context.Context, profile string, regions []string) ([]AWSSecurityGroupFinding, error) {
	var cfgOpts []func(*config.LoadOptions) error
	if profile != "" {
		cfgOpts = append(cfgOpts, config.WithSharedConfigProfile(profile))
	}

	baseCfg, err := config.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("loading AWS credentials: %w", err)
	}

	if len(regions) == 0 {
		if baseCfg.Region == "" {
			return nil, fmt.Errorf("no AWS region configured; set --aws-regions or configure a default region")
		}
		regions = []string{baseCfg.Region}
	}

	var findings []AWSSecurityGroupFinding

	for _, region := range regions {
		regionCfg := baseCfg.Copy()
		regionCfg.Region = region

		client := ec2.NewFromConfig(regionCfg)

		regionFindings, err := scanAWSRegion(ctx, client)
		if err != nil {
			return findings, fmt.Errorf("region %s: %w", region, err)
		}
		findings = append(findings, regionFindings...)
	}

	return findings, nil
}

func scanAWSRegion(ctx context.Context, client *ec2.Client) ([]AWSSecurityGroupFinding, error) {
	var findings []AWSSecurityGroupFinding

	paginator := ec2.NewDescribeSecurityGroupsPaginator(client, &ec2.DescribeSecurityGroupsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeSecurityGroups: %w", err)
		}

		for _, sg := range page.SecurityGroups {
			insecure := insecureAWSIngressRules(sg.IpPermissions)
			if len(insecure) == 0 {
				continue
			}
			findings = append(findings, AWSSecurityGroupFinding{
				ID:            aws.ToString(sg.GroupId),
				Name:          aws.ToString(sg.GroupName),
				InsecureRules: insecure,
			})
		}
	}

	return findings, nil
}

// insecureAWSIngressRules extracts the subset of ingress permissions that allow traffic from 0.0.0.0/0 or ::/0, for any protocol/port.
func insecureAWSIngressRules(perms []types.IpPermission) []InsecureRule {
	var out []InsecureRule

	for _, perm := range perms {
		protocol := awsProtocolName(aws.ToString(perm.IpProtocol))
		port := awsPortString(perm)

		for _, ipRange := range perm.IpRanges {
			cidr := aws.ToString(ipRange.CidrIp)
			if isInternetCIDR(cidr) {
				out = append(out, InsecureRule{
					Protocol: protocol,
					Port:     port,
					Source:   cidr,
				})
			}
		}
		for _, ipRange := range perm.Ipv6Ranges {
			cidr := aws.ToString(ipRange.CidrIpv6)
			if isInternetCIDR(cidr) {
				out = append(out, InsecureRule{
					Protocol: protocol,
					Port:     port,
					Source:   cidr,
				})
			}
		}
	}

	return out
}

// awsProtocolName normalizes AWS's IpProtocol field. AWS uses "-1" to mean "all protocols".
func awsProtocolName(proto string) string {
	if proto == "-1" {
		return "all"
	}
	return proto
}

// awsPortString renders the port or port range for a permission. AWS omits FromPort/ToPort entirely when the rule covers all ports
// (e.g. protocol "-1", or ICMP where the fields mean something else).
func awsPortString(perm types.IpPermission) string {
	if perm.FromPort == nil || perm.ToPort == nil {
		return "all"
	}
	from := *perm.FromPort
	to := *perm.ToPort

	// AWS represents "all ports" for protocol -1 as FromPort/ToPort = -1.
	if from == -1 && to == -1 {
		return "all"
	}
	if from == to {
		return strconv.FormatInt(int64(from), 10)
	}
	return fmt.Sprintf("%d-%d", from, to)
}
