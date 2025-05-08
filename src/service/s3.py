import os
import json
import aioboto3
from datetime import datetime
from mcp.server.fastmcp import FastMCP
from dotenv import load_dotenv
from typing import List, Optional

# Load environment variables from .env file
load_dotenv()

# Initialize MCP server
mcp = FastMCP("s3_security_report")

# Helper to validate AWS credentials
def validate_credentials():
    required_keys = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
    for key in required_keys:
        if not os.getenv(key):
            return f"Error: {key} is not set in .env file."
    return None

# Helper to get bucket region
async def get_bucket_region(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        return location if location else 'us-east-1'
    except s3.exceptions.ClientError as e:
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketLocation)"
    except Exception as e:
        return f"Error: {str(e)}"

# Security check functions with comprehensive error handling
async def check_overbroad_access(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_policy_status(Bucket=bucket_name)
        is_public = response['PolicyStatus']['IsPublic']
        return "Pass: Bucket is not publicly accessible" if not is_public else "Fail: Bucket is publicly accessible"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return "Pass: No bucket policy exists (not public by policy)"
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketPolicyStatus)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_cross_account_access(s3, bucket_name: str, owner_id: str) -> str:
    try:
        response = await s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        cross_account_principals = []
        for statement in policy.get('Statement', []):
            if statement['Effect'] == 'Allow':
                principal = statement.get('Principal', {})
                if isinstance(principal, dict):
                    aws_principals = principal.get('AWS', [])
                    if isinstance(aws_principals, str):
                        aws_principals = [aws_principals]
                    for p in aws_principals:
                        if p.startswith('arn:aws:iam::'):
                            account_id = p.split(':')[4]
                            if account_id != owner_id and account_id not in cross_account_principals:
                                cross_account_principals.append(account_id)
        return f"Warning: Allows access to accounts {', '.join(cross_account_principals)}" if cross_account_principals else "Pass: No cross-account access detected"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return "Pass: No bucket policy exists (no cross-account access)"
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketPolicy)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_secure_transport(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        for statement in policy.get('Statement', []):
            if statement['Effect'] == 'Deny' and 'Condition' in statement:
                condition = statement['Condition']
                if 'Bool' in condition and 'aws:SecureTransport' in condition['Bool']:
                    if condition['Bool']['aws:SecureTransport'] == 'false':
                        return "Pass: HTTPS enforced by policy"
        return "Fail: No policy enforcing HTTPS detected"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return "Fail: No bucket policy exists to enforce HTTPS"
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketPolicy)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_server_side_encryption(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        return "Pass: Server-side encryption enabled" if rules else "Fail: No server-side encryption configured"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return "Fail: No server-side encryption configured"
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketEncryption)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_kms_encryption(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_encryption(Bucket=bucket_name)
        rules = response['ServerSideEncryptionConfiguration']['Rules']
        for rule in rules:
            if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] == 'aws:kms':
                if 'KMSMasterKeyID' in rule['ApplyServerSideEncryptionByDefault']:
                    return "Pass: KMS encryption with customer-managed key enabled"
                return "Fail: KMS encryption uses AWS-managed key"
        return "Fail: No KMS encryption configured"
    except s3.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return "Fail: No encryption configured"
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketEncryption)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_versioning(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        return "Pass: Versioning enabled" if status == 'Enabled' else "Fail: Versioning not enabled"
    except s3.exceptions.ClientError as e:
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketVersioning)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_mfa_delete(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_versioning(Bucket=bucket_name)
        mfa_delete = response.get('MFADelete', 'Disabled')
        return "Pass: MFA Delete enabled" if mfa_delete == 'Enabled' else "Fail: MFA Delete not enabled"
    except s3.exceptions.ClientError as e:
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketVersioning)"
    except Exception as e:
        return f"Error: {str(e)}"

async def check_access_logging(s3, bucket_name: str) -> str:
    try:
        response = await s3.get_bucket_logging(Bucket=bucket_name)
        logging_enabled = response.get('LoggingEnabled') is not None
        return "Pass: Access logging enabled" if logging_enabled else "Fail: Access logging not enabled"
    except s3.exceptions.ClientError as e:
        return f"Error: {str(e)} (check IAM permissions: s3:GetBucketLogging)"
    except Exception as e:
        return f"Error: {str(e)}"

# Main tool function
@mcp.tool()
async def s3_security_report(bucket_names: Optional[List[str]] = None, region: Optional[str] = None) -> str:
    """Generate a security report for S3 buckets.

    Args:
        bucket_names: List of bucket names to check. If empty or None, check all buckets.
        region: AWS region to filter buckets by. If None, consider all regions.
    """
    # Validate credentials
    cred_error = validate_credentials()
    if cred_error:
        return cred_error

    session = aioboto3.Session()
    async with session.client('s3') as s3:
        try:
            # Fetch all buckets
            response = await s3.list_buckets()
            all_buckets = response.get('Buckets', [])
            owner_id = response.get('Owner', {}).get('ID', 'Unknown')

            if not all_buckets:
                return "No S3 buckets found in the account."

            # Select buckets based on input
            selected_buckets = []
            missing_buckets = set(bucket_names) if bucket_names else set()

            if bucket_names:
                selected_buckets = [b for b in all_buckets if b['Name'] in bucket_names]
                missing_buckets = missing_buckets - {b['Name'] for b in selected_buckets}
            else:
                selected_buckets = all_buckets

            # Enrich buckets with region information
            for bucket in selected_buckets:
                bucket['Region'] = await get_bucket_region(s3, bucket['Name'])

            # Filter by region if specified and no specific bucket names provided
            if not bucket_names and region:
                selected_buckets = [b for b in selected_buckets if b['Region'] == region]

            if not selected_buckets:
                if region:
                    return f"No S3 buckets found in region {region}."
                return "No S3 buckets found matching the criteria."

            # Generate report
            report = "# S3 Security Report\n\n"
            if missing_buckets:
                report += "## Missing Buckets\nThe following buckets were not found or access is denied:\n"
                report += "\n".join(f"- {name}" for name in sorted(missing_buckets)) + "\n\n"

            for bucket in sorted(selected_buckets, key=lambda x: x['Name']):
                report += f"## Bucket: {bucket['Name']}\n"
                report += f"- Region: {bucket['Region']}\n"
                report += f"- Creation Date: {bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S %Z')}\n"
                report += "- Security Checks:\n"

                checks = {
                    "Overbroad S3 Access Control": await check_overbroad_access(s3, bucket['Name']),
                    "Cross-Account Access": await check_cross_account_access(s3, bucket['Name'], owner_id),
                    "Secure Transport": await check_secure_transport(s3, bucket['Name']),
                    "Server-Side Encryption": await check_server_side_encryption(s3, bucket['Name']),
                    "KMS Customer Master Keys": await check_kms_encryption(s3, bucket['Name']),
                    "Versioning": await check_versioning(s3, bucket['Name']),
                    "MFA Delete": await check_mfa_delete(s3, bucket['Name']),
                    "Access Logging": await check_access_logging(s3, bucket['Name']),
                }

                for check_name, result in checks.items():
                    report += f"  - {check_name}: {result}\n"
                report += "\n"

                # Recommendations
                report += "### Recommendations\n"
                recommendations = []
                if "Fail" in checks["Overbroad S3 Access Control"]:
                    recommendations.append("- **Restrict Public Access**: Update bucket policy to deny public access or enable Block Public Access settings.")
                if "Warning" in checks["Cross-Account Access"]:
                    recommendations.append("- **Review Cross-Account Access**: Verify that cross-account permissions are intentional and remove unnecessary access.")
                if "Fail" in checks["Secure Transport"]:
                    recommendations.append("- **Enforce HTTPS**: Add a bucket policy to deny non-HTTPS requests (aws:SecureTransport=false).")
                if "Fail" in checks["Server-Side Encryption"]:
                    recommendations.append("- **Enable Encryption**: Configure server-side encryption with AES-256 or KMS.")
                if "Fail" in checks["KMS Customer Master Keys"]:
                    recommendations.append("- **Use KMS**: Configure encryption with customer-managed KMS keys for better control.")
                if "Fail" in checks["Versioning"]:
                    recommendations.append("- **Enable Versioning**: Turn on versioning to protect against accidental deletions.")
                if "Fail" in checks["MFA Delete"]:
                    recommendations.append("- **Enable MFA Delete**: Enable MFA Delete for enhanced deletion protection (requires versioning).")
                if "Fail" in checks["Access Logging"]:
                    recommendations.append("- **Enable Logging**: Configure server access logging to a target bucket for audit trails.")
                report += "\n".join(recommendations) or "- No recommendations needed; all checks passed."
                report += "\n\n"

            return report
        except s3.exceptions.ClientError as e:
            return f"Error accessing S3 service: {str(e)} (check IAM permissions: s3:ListAllMyBuckets)"
        except Exception as e:
            return f"Error generating S3 security report: {str(e)}"

if __name__ == "__main__":
    mcp.run(transport='stdio')