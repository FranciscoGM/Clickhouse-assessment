<h2>Tasks</h2>

#################################################################################
<h3>CloudFormation template</h3>
	-	Identify at least three security issues with the CloudFormation template.
	-	Write an improved version of the CloudFormation template that follows AWS security best practices.
	-	Assuming the user with these permissions exists in the environment, how would you go about finding misconfigurations like this and how would you fix this?
#################################################################################

<h4>Identify at least three security issues with the CloudFormation template.</h4>

1. Instead of using role-based acces, an IAM user is created with an inline policy attached granting full permissions, effectively giving admin access to everything on the AWS account.
2. The S3 bucket is created without the <i>BucketEncryption</i> property, meaning data at rest may not be encrypted.
3. The S3 bucket is created without the <i>PublicAccessBlockConfiguration</i> property, meaning that no access controls or public access protection are implemented.


<h4>Write an improved version of the CloudFormation template that follows AWS security best practices.</h4>

Solution in the <b>CloudFormationSecure.yaml</b> file included in the repo.


<h4>Assuming the user with these permissions exists in the environment, how would you go about finding misconfigurations like this and how would you fix this?</h4>

Assuming a user with full permissions exist in the AWS environment, I would leverage AWS native tools like AWS Config, Trusted Advisor or Security Hub (third-party tools could also be used) to identify misconfigurations like this one, not aligned with security best-practices.

To fix it, I would update the IaC ensuring least privilege is applied, prioritizing the use of roles over IAM users.

We could go <i>further left</i> by implementing static IaC and security checks (using tools like Checkov or Trivy) on CICD pipelines to idenfify this issues early and block deployment pipelines preventing this issues from being deployed to production environments.


#################################################################################
<h3>Dockerfile</h3>
	-	What are the issues with the Dockerfile?
#################################################################################

1. The Dockerfile uses an outdated base image. Ubuntu 18.04 is EOL since May 2023, potentially leaving it exposed to unpatched vulnerabilities
2. The container runs as root, potentially allowing an attacker to escape the container and gain full control over the host system.
3. There are hardcoded secrets in the Dockerfile (DB_PASSWORD and API_KEY), leaving them exposed to anyone with access to the image.
4. Overly broad filesystem permissions are granted to /app, breaking the least privilege principle and unnecessarily granting full access to all users.
5. Potentially unneeded packages are installed (vim, curl, dnsutils) that could pose additional unnecesary risk expanding the attack surface.
6. The Dockerfile copies the entire context blindly (COPY . /app) without a <i>.dockerignore</d> file, which may potentially include sensitive files.
7. Unsafe port 80 is exposed, which may be avoided.



#################################################################################
<h3>How would you prevent the misconfigurations from being introduced/applied to the environment for both files?</h3>
#################################################################################

To prevent misconfigurations from being introduced to the environment by CFN templates and Dockerfiles I would integrate static IaC and security checks using tools like Trivy and configuring pre-commit hooks.
