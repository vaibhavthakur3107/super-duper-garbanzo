# Cloud Security Assessment Methodology

## AWS Security Checklist

### IAM
- Check for root account MFA: `aws iam get-account-summary`
- List overly-permissive policies: `aws iam list-policies --scope Local`
- Find privilege escalation paths via `iam:PassRole` + `ec2:RunInstances`
- Check for unused/stale access keys: `aws iam generate-credential-report`

### S3 Buckets
- List buckets: `aws s3 ls`
- Check public ACL: `aws s3api get-bucket-acl --bucket BUCKET_NAME`
- Check bucket policy: `aws s3api get-bucket-policy --bucket BUCKET_NAME`
- Test anonymous access: `aws s3 ls s3://BUCKET_NAME --no-sign-request`

### EC2 & Metadata
- Test IMDS v1 (SSRF): `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/`
- List security groups: check for 0.0.0.0/0 on sensitive ports
- Check for unencrypted EBS volumes

### Prowler (CIS Benchmark)
- `prowler aws -M csv -S -g cislevel1` — CIS Level 1 checks
- `prowler aws -c extra7102` — check for publicly accessible RDS

## Azure Security Checklist
- `az ad users list --query '[].{UPN:userPrincipalName}'` — enumerate users
- `az role assignment list --all` — check RBAC assignments
- Storage account public access: `az storage account list --query '[].allowBlobPublicAccess'`

## GCP Security Checklist
- `gcloud iam service-accounts list` — enumerate service accounts
- Check for org policy violations: `gcloud resource-manager org-policies list`
- Bucket ACL: `gsutil iam get gs://BUCKET_NAME`

## Container Security

### Docker
```bash
# CIS Docker Benchmark
docker-bench-security

# Scan image for CVEs
trivy image nginx:latest
trivy image --severity HIGH,CRITICAL TARGET_IMAGE

# Check for secrets in image layers
docker history --no-trunc TARGET_IMAGE
```

### Dockerfile Best Practices
- Use non-root USER
- Multi-stage builds to reduce attack surface
- No hardcoded secrets (use ARG + build secrets)
- Pin base image tags

## Kubernetes Security

### Cluster Enumeration
```bash
kube-hunter --remote CLUSTER_IP    # passive scan
kube-hunter --remote CLUSTER_IP --active  # active exploit attempts

# Check kubelet unauthenticated API (port 10250)
curl -k https://NODE_IP:10250/pods

# Check etcd exposure (port 2379)
curl -k https://ETCD_IP:2379/v2/keys/?recursive=true
```

### RBAC Review
```bash
kubectl get clusterrolebindings -o json | jq '.items[] | .subjects,.roleRef'
kubectl auth can-i --list --as system:anonymous
kubectl auth can-i --list --as system:unauthenticated
```

### Common K8s Vulnerabilities
- Privileged container → host escape
- `hostPath` volume mount → access host filesystem
- `automountServiceAccountToken: true` → credential theft
- Default namespace service account with cluster-admin

## Secrets Detection
```bash
trufflehog git https://github.com/ORG/REPO --only-verified
gitleaks detect --source . --report-path secrets.json
grep -rn "AWS_SECRET\|api_key\|private_key" ~/.kube/
```
