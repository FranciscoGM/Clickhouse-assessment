# Python Storage Buckets Security Checks

Multi-cloud storage bucket security auditor.

Scans storage buckets/containers across AWS S3, Google Cloud Storage (GCS), and Azure Blob Storage, checks each for public accessibility and encryption-at-rest configuration, and writes results to a CSV report.

## Authentication

Uses each provider's standard SDK credential chain (no hardcoded credentials):

- **AWS:** `aws configure`, env vars (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`), an IAM role, or `AWS_PROFILE`.
- **GCP:** `gcloud auth application-default login`, a service account key via `GOOGLE_APPLICATION_CREDENTIALS`, or workload identity. Needs a project ID and `storage.buckets.getIamPolicy` permission.
- **Azure:** `az login`, a service principal, or managed identity via `DefaultAzureCredential`. Needs Storage Account Reader/Contributor role to enumerate accounts.

## Install

```
pip3 install boto3 google-cloud-storage azure-identity \
            azure-mgmt-storage azure-storage-blob
```

## Usage

```
python3 cloud_bucket_audit.py \
    --gcp-project my-gcp-project \
    --azure-subscription-id 00000000-0000-0000-0000-000000000000 \
    --output bucket_report.csv \
    --providers aws gcp azure
```
