#**Clickhouse take-home assessment**

##**1. Secure GCP Infrastructure with Terraform**
Write a Terraform module that deploys the following resources securely in Google Cloud Platform (GCP):
####**Requirements**
● A VPC network with a public and private subnet.
● A Compute Engine instance in the private subnet.
● A Global HTTP Load Balancer in the public subnet that routes traffic to the Compute Engine instance.
● Firewall rules that:
  ○ Allow only HTTPS (443) from the internet to the Load Balancer.
  ○ Allow only SSH (22) from a trusted IP range (not 0.0.0.0/0) to the Compute Engine instance.
  ○ Allow only HTTP (80) from the Load Balancer to the Compute Engine instance.

**Bonus**: Implement least privilege IAM roles for resources instead of using roles/editor or roles/owner.

##**2. Cloud Security Check**
You are given a CloudFormation template (YAML format) and a Dockerfile file.

####**Tasks**
● CloudFormation template
  ○ Identify at least three security issues with the CloudFormation template.
  ○ Write an improved version of the CloudFormation template that follows AWS security best practices.
  ○ Assuming the user with these permissions exists in the environment, how would you go about finding misconfigurations like this and how would you fix this?
● Dockerfile
  ○ What are the issues with the Dockerfile?
● How would you prevent the misconfigurations from being introduced/applied to the environment for both files?

##**3. Automate Security Checks with Go**
####**Task**
Write a Go CLI tool that:
● Scans AWS, GCP, and Azure firewall/security group rules.
● Detects any rule that allows inbound traffic from 0.0.0.0/0 (open to the internet) for any protocol and any port.
● Outputs the list of insecure rules in JSON format.

####**Expected Implementation**
Your Go program should:
1. Authenticate with AWS, GCP, and Azure.
2. Fetch all firewall/security group rules from each cloud provider.
3. Identify rules where 0.0.0.0/0 is allowed for any protocol/port.
4. Output the findings in JSON format.

####Cloud-Specific Details
AWS Security Check
● Use the AWS SDK for Go to list EC2 Security Groups.
● Identify rules allowing inbound traffic from 0.0.0.0/0 for any protocol/port.

##GCP Security Check
● Use the Google Cloud SDK for Go to list Firewall rules.
● Look for sourceRanges: ["0.0.0.0/0"] allowing any protocol/port.

##Azure Security Check
● Use the Azure SDK for Go to list Network Security Groups (NSGs).
● Look for NSG rules allowing "Any" source (0.0.0.0/0) for any protocol/port.

##**4. Automate Security Checks with Python**
####**Task**
Write a Python script that:
● Lists all storage buckets in AWS (S3), GCP (GCS), and Azure (Blob Storage).
● Checks if each bucket has:
  ○ Public access enabled (Yes/No).
  ○ Encryption enabled (Yes/No).
● Generates a CSV report containing:
  ○ Cloud Provider (AWS, GCP, Azure)
  ○ Bucket Name
  ○ Public Access Status (Yes/No)
  ○ Encryption Status (Yes/No)

####**Expected Implementation**
Your Python script should:
1. Authenticate with AWS, GCP, and Azure.
2. Fetch all storage buckets.
3. Check public access and encryption settings.
4. Generate a CSV report.

####**Cloud-Specific Details**
####AWS (S3) Checks
● Use Boto3 (AWS SDK for Python) to:
● List S3 Buckets.
● Check public access block settings.
● Check if default encryption is enabled.

####GCP (Google Cloud Storage - GCS) Checks
● Use Google Cloud SDK for Python to:
● List GCS Buckets.
● Check if the bucket is public (IAM policies).
● Check if default encryption is enabled.

####Azure (Blob Storage) Checks
● Use Azure SDK for Python to:
● List Azure Blob Storage Containers.
● Check if public access is enabled.
● Check if encryption is enabled.

##**Third-Party Dependency Security Audit**
####**Scenario**
You are given a package.json file containing dependencies for a Node.js application. Your task is to scan it for vulnerabilities, analyze the results, and provide security recommendations.

####**Instructions**
1. Analyze the given package.json to identify security vulnerabilities.
2. Use at least one vulnerability scanning tool, such as:
  ○ npm audit
  ○ yarn audit
  ○ snyk test
  ○ OWASP Dependency-Check
3. Document:
  ○ The list of detected vulnerabilities (high/critical priority).
  ○ Which dependencies are vulnerable.
  ○ How to fix the issues (e.g., updating the package, replacing dependencies).
  ○ How many issues can be fixed.
4. Bonus: Automate the scan with a Python or Go script that:
  ○ Parses the vulnerabilities.
  ○ Generates a CSV or JSON report.

####**Expected Deliverables**
● A list of vulnerabilities (e.g., "Lodash prototype pollution vulnerability in version 4.17.10").
● Remediation steps (e.g., "Upgrade lodash to 4.17.21").
● A script (optional bonus) to automate vulnerability reporting.
