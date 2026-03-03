"""
CI/CD Evidence Ingest Script
=============================
Called directly from GitHub Actions after each security scan.
Normalizes scan results to AWS ASFF and pushes to:
  - Security Hub  (BatchImportFindings)
  - Audit Manager (BatchImportEvidenceToAssessmentControl)

Usage:
  python scripts/ingest.py \
    --type sast|dast|container|dependency \
    --tool bandit|semgrep|zap|trivy|pip-audit \
    --file <results-file.json> \
    --repo <github-repo> \
    --commit <sha> \
    --run-id <github-run-id>

AWS credentials come from the environment (GitHub Actions OIDC or secrets).
"""

import argparse
import json
import os
import sys
import datetime
import hashlib
import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
AWS_ACCOUNT_ID = os.environ.get("AWS_ACCOUNT_ID", "")
ASSESSMENT_ID = os.environ.get("AUDIT_MANAGER_ASSESSMENT_ID", "")

CONTROL_MAP = {
    "sast":       ["SA-11", "SA-15"],
    "dependency": ["SI-2",  "SA-12"],
    "container":  ["CM-7",  "SI-3",  "CM-6"],
    "dast":       ["CA-8",  "SA-11"],
}

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "MODERATE": "MEDIUM",
    "LOW":      "LOW",
    "INFO":     "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--type",   required=True, choices=["sast", "dast", "container", "dependency"])
    parser.add_argument("--tool",   required=True)
    parser.add_argument("--file",   required=True)
    parser.add_argument("--repo",   default=os.environ.get("GITHUB_REPOSITORY", "unknown"))
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA", "unknown"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID", "unknown"))
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"[ingest] No results file at {args.file} — skipping.")
        sys.exit(0)

    with open(args.file) as f:
        try:
            raw = json.load(f)
        except json.JSONDecodeError:
            print(f"[ingest] Could not parse {args.file} as JSON — skipping.")
            sys.exit(0)

    print(f"[ingest] Processing {args.tool} ({args.type}) results from {args.file}")

    findings = normalize(args.type, args.tool, raw, args.repo, args.commit, args.run_id)
    print(f"[ingest] Normalized {len(findings)} findings")

    if findings:
        push_to_security_hub(findings)

    push_to_audit_manager(args.type, args.tool, args.file, raw, args.repo, args.commit, args.run_id)


# ---------------------------------------------------------------------------
# Normalization — scan JSON → ASFF
# ---------------------------------------------------------------------------
def normalize(scan_type, tool, raw, repo, commit, run_id):
    if tool == "bandit":
        return _from_bandit(raw, repo, commit, run_id)
    if tool == "semgrep":
        return _from_semgrep(raw, repo, commit, run_id)
    if tool == "trivy":
        return _from_trivy(raw, repo, commit, run_id)
    if tool in ("pip-audit", "pip_audit"):
        return _from_pip_audit(raw, repo, commit, run_id)
    if tool == "zap":
        return _from_zap(raw, repo, commit, run_id)
    print(f"[ingest] No normalizer for tool '{tool}' — skipping Security Hub import.")
    return []


def _asff_base(tool, repo, commit, run_id):
    return {
        "SchemaVersion": "2018-10-08",
        "ProductArn": f"arn:aws:securityhub:{AWS_REGION}:{AWS_ACCOUNT_ID}:product/{AWS_ACCOUNT_ID}/default",
        "AwsAccountId": AWS_ACCOUNT_ID,
        "CreatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "UpdatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "GeneratorId": f"cicd/{tool}",
        "ProductFields": {
            "cicd/tool":      tool,
            "cicd/repo":      repo,
            "cicd/commit":    commit[:40],
            "cicd/run_id":    str(run_id),
        },
        "Resources": [{
            "Type":      "Other",
            "Id":        f"arn:aws:github:::repository/{repo}",
            "Partition": "aws",
            "Region":    AWS_REGION,
        }],
    }


def _finding_id(tool, key):
    h = hashlib.sha256(f"{tool}/{key}".encode()).hexdigest()[:16]
    return f"arn:aws:securityhub:{AWS_REGION}:{AWS_ACCOUNT_ID}:finding/{tool}/{h}"


def _from_bandit(raw, repo, commit, run_id):
    results = raw.get("results", [])
    findings = []
    for r in results:
        sev = SEVERITY_MAP.get(r.get("issue_severity", "MEDIUM").upper(), "MEDIUM")
        base = _asff_base("bandit", repo, commit, run_id)
        base.update({
            "Id":          _finding_id("bandit", f"{r.get('filename')}:{r.get('line_number')}:{r.get('test_id')}"),
            "Title":       f"[Bandit] {r.get('test_name', 'Security Issue')}",
            "Description": r.get("issue_text", ""),
            "Severity":    {"Label": sev},
            "Types":       ["Software and Configuration Checks/Vulnerabilities/CVE"],
        })
        findings.append(base)
    return findings


def _from_semgrep(raw, repo, commit, run_id):
    runs = raw.get("runs", [])
    findings = []
    for run in runs:
        for r in run.get("results", []):
            sev_raw = r.get("properties", {}).get("severity", "medium").upper()
            sev = SEVERITY_MAP.get(sev_raw, "MEDIUM")
            base = _asff_base("semgrep", repo, commit, run_id)
            msg = r.get("message", {})
            text = msg.get("text", "") if isinstance(msg, dict) else str(msg)
            loc = r.get("locations", [{}])[0]
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "unknown")
            base.update({
                "Id":          _finding_id("semgrep", f"{uri}:{r.get('ruleId','')}"),
                "Title":       f"[Semgrep] {r.get('ruleId', 'Rule violation')}",
                "Description": text[:1024],
                "Severity":    {"Label": sev},
                "Types":       ["Software and Configuration Checks/Vulnerabilities/CVE"],
            })
            findings.append(base)
    return findings


def _from_trivy(raw, repo, commit, run_id):
    findings = []
    for result in raw.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            sev_raw = v.get("Severity", "MEDIUM").upper()
            sev = SEVERITY_MAP.get(sev_raw, "MEDIUM")
            base = _asff_base("trivy", repo, commit, run_id)
            base.update({
                "Id":          _finding_id("trivy", f"{v.get('PkgName')}:{v.get('VulnerabilityID')}"),
                "Title":       f"[Trivy] {v.get('VulnerabilityID', 'CVE')} in {v.get('PkgName', '')}",
                "Description": v.get("Description", v.get("Title", ""))[:1024],
                "Severity":    {"Label": sev},
                "Types":       ["Software and Configuration Checks/Vulnerabilities/CVE"],
            })
            findings.append(base)
    return findings


def _from_pip_audit(raw, repo, commit, run_id):
    findings = []
    dependencies = raw if isinstance(raw, list) else raw.get("dependencies", [])
    for dep in dependencies:
        for v in dep.get("vulns", []):
            base = _asff_base("pip-audit", repo, commit, run_id)
            base.update({
                "Id":          _finding_id("pip-audit", f"{dep.get('name')}:{v.get('id')}"),
                "Title":       f"[pip-audit] {v.get('id')} in {dep.get('name')} {dep.get('version','')}",
                "Description": v.get("description", "")[:1024],
                "Severity":    {"Label": "HIGH"},
                "Types":       ["Software and Configuration Checks/Vulnerabilities/CVE"],
            })
            findings.append(base)
    return findings


def _from_zap(raw, repo, commit, run_id):
    findings = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0].upper()
            sev = SEVERITY_MAP.get(risk, "MEDIUM")
            base = _asff_base("zap", repo, commit, run_id)
            base.update({
                "Id":          _finding_id("zap", f"{alert.get('pluginid')}:{alert.get('name','')}"),
                "Title":       f"[ZAP] {alert.get('name', 'Web vulnerability')}",
                "Description": alert.get("desc", "")[:1024],
                "Severity":    {"Label": sev},
                "Types":       ["Software and Configuration Checks/Vulnerabilities/CVE"],
            })
            findings.append(base)
    return findings


# ---------------------------------------------------------------------------
# Security Hub import
# ---------------------------------------------------------------------------
def push_to_security_hub(findings):
    sh = boto3.client("securityhub", region_name=AWS_REGION)
    batch_size = 100
    imported = 0
    failed = 0
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        try:
            resp = sh.batch_import_findings(Findings=batch)
            imported += resp.get("SuccessCount", 0)
            failed   += resp.get("FailedCount", 0)
            if resp.get("FailedFindings"):
                for ff in resp["FailedFindings"][:3]:
                    print(f"[ingest] SecHub failed: {ff.get('ErrorCode')} — {ff.get('ErrorMessage')}")
        except ClientError as e:
            print(f"[ingest] SecurityHub BatchImportFindings error: {e}")
    print(f"[ingest] SecurityHub: {imported} imported, {failed} failed")


# ---------------------------------------------------------------------------
# Audit Manager evidence import
# ---------------------------------------------------------------------------
def push_to_audit_manager(scan_type, tool, file_path, raw, repo, commit, run_id):
    if not ASSESSMENT_ID:
        print("[ingest] AUDIT_MANAGER_ASSESSMENT_ID not set — skipping Audit Manager import.")
        return

    am = boto3.client("auditmanager", region_name=AWS_REGION)

    nist_controls = CONTROL_MAP.get(scan_type, [])
    if not nist_controls:
        return

    try:
        assessment = am.get_assessment(assessmentId=ASSESSMENT_ID)
    except ClientError as e:
        print(f"[ingest] Could not fetch assessment: {e}")
        return

    control_sets = assessment["assessment"]["framework"].get("controlSets", [])

    evidence_text = json.dumps({
        "tool":       tool,
        "scan_type":  scan_type,
        "repository": repo,
        "commit":     commit,
        "run_id":     str(run_id),
        "timestamp":  datetime.datetime.utcnow().isoformat(),
        "summary":    _summarize(scan_type, tool, raw),
    }, indent=2)

    imported = 0
    for cs in control_sets:
        cs_id = cs["id"]
        for ctrl in cs.get("controls", []):
            ctrl_id   = ctrl["id"]
            ctrl_name = ctrl.get("name", "")
            if any(nc.replace("-", " ") in ctrl_name.upper() or nc in ctrl_name.upper()
                   for nc in nist_controls):
                try:
                    am.batch_import_evidence_to_assessment_control(
                        assessmentId=ASSESSMENT_ID,
                        controlSetId=cs_id,
                        controlId=ctrl_id,
                        manualEvidence=[{"textResponse": evidence_text[:2048]}],
                    )
                    imported += 1
                    print(f"[ingest] AuditManager: evidence imported to {ctrl_name} ({ctrl_id})")
                except ClientError as e:
                    print(f"[ingest] AuditManager import error for {ctrl_id}: {e}")

    if imported == 0:
        print(f"[ingest] AuditManager: no matching controls found for {nist_controls}")
    else:
        print(f"[ingest] AuditManager: imported evidence to {imported} controls")


def _summarize(scan_type, tool, raw):
    if tool == "bandit":
        results = raw.get("results", [])
        return {
            "total": len(results),
            "high":   sum(1 for r in results if r.get("issue_severity", "").upper() == "HIGH"),
            "medium": sum(1 for r in results if r.get("issue_severity", "").upper() == "MEDIUM"),
            "low":    sum(1 for r in results if r.get("issue_severity", "").upper() == "LOW"),
        }
    if tool in ("pip-audit", "pip_audit"):
        deps = raw if isinstance(raw, list) else raw.get("dependencies", [])
        vulns = sum(len(d.get("vulns", [])) for d in deps)
        return {"total_vulnerabilities": vulns}
    if tool == "trivy":
        vulns = sum(len(r.get("Vulnerabilities", [])) for r in raw.get("Results", []))
        return {"total_vulnerabilities": vulns}
    if tool == "zap":
        alerts = sum(len(s.get("alerts", [])) for s in raw.get("site", []))
        return {"total_alerts": alerts}
    return {"raw_keys": list(raw.keys()) if isinstance(raw, dict) else []}


if __name__ == "__main__":
    main()
