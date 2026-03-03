# NR Labs GRC Demo App

A simple Flask web application deployed on AWS EC2 (free tier) to demonstrate the CI/CD evidence pipeline.

## What this does

Every push to `main` triggers GitHub Actions to:
1. Build the Docker image and push to ECR
2. Run Bandit (Python SAST)
3. Run Semgrep (multi-language SAST)
4. Run pip-audit (dependency vulnerability scan)
5. Run Trivy (container vulnerability scan)
6. Run OWASP ZAP (DAST against the live EC2 instance)
7. Import all findings into **AWS Security Hub** and **AWS Audit Manager** via `scripts/ingest.py`

## Infrastructure

- **App host:** EC2 t2.micro at `3.221.97.145:5000` (free tier)
- **Container registry:** ECR `nrlabs-grc-demo-app`
- **Evidence destination:** Security Hub (ASFF findings) + Audit Manager assessment `e53a19d3-86f6-4ad2-ac6d-00d81d7c6eab`

## GitHub Actions Secrets Required

| Secret | Value |
|--------|-------|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `AWS_ACCOUNT_ID` | `834241034622` |
| `AUDIT_MANAGER_ASSESSMENT_ID` | `e53a19d3-86f6-4ad2-ac6d-00d81d7c6eab` |

## NIST 800-53 Control Mapping

| Scan | NIST Controls |
|------|--------------|
| SAST (Bandit, Semgrep) | SA-11, SA-15 |
| Dependencies (pip-audit) | SI-2, SA-12 |
| Container (Trivy) | CM-7, SI-3, CM-6 |
| DAST (OWASP ZAP) | CA-8, SA-11 |

## Local development

```bash
cd app
pip install -r requirements.txt
python app.py
# App runs at http://localhost:5000
```
