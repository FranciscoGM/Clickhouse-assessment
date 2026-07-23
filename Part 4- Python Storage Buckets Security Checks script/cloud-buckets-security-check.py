#!/usr/bin/env python3

import boto3, argparse, csv, sys
from dataclasses import dataclass, asdict
from typing import List, Optional

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cloud_bucket_audit")

# For output
@dataclass
class BucketRecord:
    cloud: str
    bucket_name: str
    public_access: str
    encryption_enabled: str


# --------------------------------------------------------------------------
# AWS S3
# --------------------------------------------------------------------------
def audit_aws(profile: Optional[str] = None, region: Optional[str] = None) -> List[BucketRecord]:
    records: List[BucketRecord] = []

    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
    except (NoCredentialsError, ClientError, BotoCoreError) as e:
        log.warning("Could not authenticate / list S3 buckets: %s", e)
        return records

    for b in buckets:
        name = b["Name"]
        public = _aws_check_public(s3, name)
        encrypted = _aws_check_encryption(s3, name)
        records.append(BucketRecord("AWS", name, public, encrypted))

    return records


def _aws_check_public(s3, bucket_name: str) -> str:
    from botocore.exceptions import ClientError

    try:
        pab = s3.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        if all(pab.get(k, False) for k in (
            "BlockPublicAcls", "IgnorePublicAcls",
            "BlockPublicPolicy", "RestrictPublicBuckets",
        )):
            return "No"
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchPublicAccessBlockConfiguration":
            log.debug("PAB check failed for %s: %s", bucket_name, e)

    try:
        status = s3.get_bucket_policy_status(Bucket=bucket_name)
        if status["PolicyStatus"]["IsPublic"]:
            return "Yes"
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("NoSuchBucketPolicy",):
            log.debug("Policy status check failed for %s: %s", bucket_name, e)

    return "No"


def _aws_check_encryption(s3, bucket_name: str) -> str:
    from botocore.exceptions import ClientError
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket_name)
        rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        return "Yes" if rules else "No"
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return "No"
        log.debug("Encryption check failed for %s: %s", bucket_name, e)
        return "Unknown"


# --------------------------------------------------------------------------
# GCP GCS
# --------------------------------------------------------------------------
def audit_gcp(project_id: Optional[str] = None) -> List[BucketRecord]:
    records: List[BucketRecord] = []
    try:
        from google.cloud import storage
        from google.api_core.exceptions import GoogleAPIError
    except ImportError:
        log.warning("google-cloud-storage not installed — skipping GCP. "
                    "`pip install google-cloud-storage`")
        return records

    try:
        client = storage.Client(project=project_id)
        buckets = list(client.list_buckets())
    except GoogleAPIError as e:
        log.warning("Could not authenticate / list GCS buckets: %s", e)
        return records
    except Exception as e:
        log.warning("GCP auth/config error: %s", e)
        return records

    for bucket in buckets:
        public = _gcp_check_public(bucket)
        encrypted = _gcp_check_encryption(bucket)
        records.append(BucketRecord("GCP", bucket.name, public, encrypted))

    return records


def _gcp_check_public(bucket) -> str:
    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)
        public_members = {"allUsers", "allAuthenticatedUsers"}
        for binding in policy.bindings:
            members = set(binding.get("members", []))
            if members & public_members:
                return "Yes"
    except Exception as e:
        log.debug("IAM policy check failed for %s: %s", bucket.name, e)
        return "Unknown"

    try:
        ubla = bucket.iam_configuration.uniform_bucket_level_access_enabled
        if not ubla:
            bucket.acl.reload()
            for entry in bucket.acl:
                entity = str(entry.get("entity", ""))
                if entity in ("allUsers", "allAuthenticatedUsers"):
                    return "Yes"
    except Exception as e:
        log.debug("ACL fallback check failed for %s: %s", bucket.name, e)

    return "No"


def _gcp_check_encryption(bucket) -> str:
    try:
        if bucket.default_kms_key_name:
            return "Yes"
        else:
            return "No"
    except Exception as e:
        log.debug("Encryption check failed for %s: %s", bucket.name, e)
        return "Unknown"


# --------------------------------------------------------------------------
# Azure Blob Storage
# --------------------------------------------------------------------------
def audit_azure(subscription_id: Optional[str] = None) -> List[BucketRecord]:
    records: List[BucketRecord] = []
    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.storage import StorageManagementClient
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        log.warning("Azure SDK not installed — skipping Azure. `pip install azure-identity azure-mgmt-storage azure-storage-blob`")
        return records

    if not subscription_id:
        log.warning("No --azure-subscription-id provided — skipping Azure.")
        return records

    try:
        credential = DefaultAzureCredential()
        storage_mgmt = StorageManagementClient(credential, subscription_id)
        accounts = list(storage_mgmt.storage_accounts.list())
    except Exception as e:
        log.warning("Could not authenticate / list Azure storage accounts: %s", e)
        return records

    for account in accounts:
        try:
            rg = account.id.split("/resourceGroups/")[1].split("/")[0]
        except (IndexError, AttributeError):
            log.debug("Could not parse resource group for %s", account.name)
            continue

        account_encrypted = _azure_check_account_encryption(account)
        account_public_allowed = getattr(account, "allow_blob_public_access", None)

        try:
            keys = storage_mgmt.storage_accounts.list_keys(rg, account.name)
            key = keys.keys[0].value
            account_url = f"https://{account.name}.blob.core.windows.net"
            blob_service = BlobServiceClient(account_url=account_url, credential=key)
            containers = blob_service.list_containers()
        except Exception as e:
            log.debug("Could not list containers for account %s: %s", account.name, e)
            continue

        for container in containers:
            bucket_label = f"{account.name}/{container.name}"
            public = _azure_check_container_public(blob_service, container.name, account_public_allowed)
            records.append(BucketRecord("Azure", bucket_label, public, account_encrypted))

    return records


def _azure_check_account_encryption(account) -> str:
    try:
        enc = account.encryption
        if enc and enc.services and enc.services.blob and enc.services.blob.enabled:
            return "Yes"
        return "No"
    except AttributeError:
        return "Unknown"


def _azure_check_container_public(blob_service, container_name: str, account_public_allowed: Optional[bool]) -> str:
    if account_public_allowed is False:
        return "No"

    try:
        client = blob_service.get_container_client(container_name)
        props = client.get_container_properties()
        return "Yes" if props.public_access else "No"
    except Exception as e:
        log.debug("Public access check failed for container %s: %s", container_name, e)
        return "Unknown"


# --------------------------------------------------------------------------
# Generate report
# --------------------------------------------------------------------------
def write_csv_report(records: List[BucketRecord], output_path: str) -> None:
    fieldnames = ["cloud", "bucket_name", "public_access", "encryption_enabled"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            row = asdict(r)
            writer.writerow({k: row[k] for k in fieldnames})


def print_summary(records: List[BucketRecord]) -> None:
    total = len(records)
    public_count = sum(1 for r in records if r.public_access == "Yes")
    unencrypted_count = sum(1 for r in records if r.encryption_enabled == "No")
    if public_count:
        log.warning("%d bucket(s) are PUBLICLY accessible — review immediately.", public_count)
    if unencrypted_count:
        log.warning("%d bucket(s) have NO encryption at rest configured.", unencrypted_count)


# --------------------------------------------------------------------------
# CLI tool
# --------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Audit AWS S3 / GCP GCS / Azure Blob Storage for public access and encryption.")
    parser.add_argument("--providers", nargs="+", choices=["aws", "gcp", "azure"], default=["aws", "gcp", "azure"], help="Which providers to scan (default: all).")
    parser.add_argument("--output", default="bucket_report.csv", help="Output CSV file path (default: bucket_report.csv).")
    parser.add_argument("--aws-profile", default=None, help="AWS named profile to use.")
    parser.add_argument("--aws-region", default=None, help="AWS region for the S3 client.")
    parser.add_argument("--gcp-project", default=None, help="GCP project ID (falls back to ADC default project if omitted).")
    parser.add_argument("--azure-subscription-id", default=None, help="Azure subscription ID to enumerate storage accounts in.")
    return parser.parse_args()


def main():
    args = parse_args()
    all_records: List[BucketRecord] = []

    if "aws" in args.providers:
        all_records.extend(audit_aws(profile=args.aws_profile, region=args.aws_region))

    if "gcp" in args.providers:
        all_records.extend(audit_gcp(project_id=args.gcp_project))

    if "azure" in args.providers:
        all_records.extend(audit_azure(subscription_id=args.azure_subscription_id))

    if not all_records:
        log.warning("No buckets found / no providers were successfully audited. Check credentials and SDK installation.")

    write_csv_report(all_records, args.output)
    print_summary(all_records)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
