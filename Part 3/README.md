# cloudfw-audit

Scans AWS Security Groups, GCP Firewall Rules, and Azure Network Security
Groups for inbound rules open to the entire internet (`0.0.0.0/0` / `::/0` /
`*` / `Internet`) on **any** protocol or port, and prints the findings as
JSON.


## Build

```bash
go mod tidy   # downloads the AWS/GCP/Azure SDKs
go build -o cloudfw-audit .
```

## Authentication

The tool never accepts credentials as flags — it uses each provider's
standard default credential chain, so it works the same way the official
CLIs do:

| Provider | How to authenticate |
|---|---|
| AWS | `aws configure` / `aws configure sso`, or standard env vars (`AWS_ACCESS_KEY_ID`, etc.), or an EC2/ECS/Lambda role. Select a non-default profile with `--aws-profile`. |
| GCP | `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a service-account key file. |
| Azure | `az login`, or standard env vars (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET`), or managed identity. |

Minimum IAM permissions needed (read-only):

- **AWS**: `ec2:DescribeSecurityGroups`
- **GCP**: `compute.firewalls.list` (the `roles/compute.viewer` role covers this)
- **Azure**: `Microsoft.Network/networkSecurityGroups/read` (the built-in `Reader` role covers this)

## Usage

```bash
./cloudfw-audit \
  --aws-regions us-east-1,eu-west-1 \
  --gcp-project my-gcp-project \
  --azure-subscription 00000000-0000-0000-0000-000000000000
```

Flags:

| Flag | Description |
|---|---|
| `--aws-profile` | Named AWS profile to use (optional). |
| `--aws-regions` | Comma-separated AWS regions to scan (optional; defaults to your configured region). |
| `--gcp-project` | GCP project ID to scan. Omit to skip the GCP scan. |
| `--azure-subscription` | Azure subscription ID to scan. Omit to skip the Azure scan. |
| `--skip-aws` / `--skip-gcp` / `--skip-azure` | Force-skip a provider even if credentials/flags are present. |
| `--timeout` | Overall scan timeout (default `2m`). |

You can scan a subset of providers, e.g. AWS only:

```bash
./cloudfw-audit --aws-regions us-east-1 --skip-gcp --skip-azure
```

## Output

JSON on stdout, matching:

```json
{
  "aws": { "security_groups": [ { "id": "...", "name": "...", "insecure_rules": [ { "protocol": "tcp", "port": "8080", "source": "0.0.0.0/0" } ] } ] },
  "gcp": { "firewall_rules": [ { "name": "...", "network": "default", "insecure_rules": [ { "protocol": "icmp", "port": "all", "source": "0.0.0.0/0" } ] } ] },
  "azure": { "nsgs": [ { "id": "...", "name": "...", "insecure_rules": [ { "protocol": "*", "port": "*", "source": "0.0.0.0/0" } ] } ] },
  "errors": [],
  "scanned_at": "2026-07-22T00:00:00Z"
}
```

- `port` is a string everywhere so it can hold a single port (`"8080"`), a
  range (`"1000-2000"`), or `"all"` / `"*"` when the rule covers every port.
- Clean security groups/rules/NSGs (nothing open) are simply omitted from
  the corresponding array — only offenders are listed.
- `errors` collects non-fatal problems (e.g. a provider skipped because no
  project/subscription was given, or an API call that failed) so one
  provider's misconfiguration doesn't abort the whole scan.
- **Exit code 2** if any insecure rule was found (useful as a CI gate),
  exit code `0` if the environment is clean, exit code `1` on a fatal error
  (e.g. couldn't encode JSON).

## Notes on detection logic

- **AWS**: flags any ingress permission (`IpPermission`) whose `IpRanges` or
  `Ipv6Ranges` contains `0.0.0.0/0` / `::/0`, regardless of protocol.
  `IpProtocol = "-1"` (AWS's "all protocols" sentinel) and a missing
  `FromPort`/`ToPort` are both reported as `"all"`.
- **GCP**: flags `INGRESS`-direction, `ALLOW`-type firewall rules (`Allowed`
  list non-empty) whose `sourceRanges` contains `0.0.0.0/0` / `::/0`. Deny
  rules are ignored since they don't open access.
- **Azure**: flags custom inbound `Allow` security rules whose
  `sourceAddressPrefix` (or any entry in `sourceAddressPrefixes`) is
  `0.0.0.0/0`, `*`, `Internet`, or `Any`. NSG default rules
  (`AllowVnetInBound`, `DenyAllInBound`, etc.) are fixed system rules and
  are not evaluated, since they can't be the source of an open rule someone
  added.

## Extending

Each provider lives in its own file (`aws.go`, `gcp.go`, `azure.go`) behind
a `scanX(ctx, ...) ([]XFinding, error)` function, so adding a new signal
(e.g. flagging risky ports like 22/3389, or egress rules) is a matter of
extending that provider's `insecureXRules` helper without touching the
others.
