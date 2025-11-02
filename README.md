# Default-Credentials-Weak-Auth-Automation
Automated detection of default, weak, or exposed credentials across network services to reduce initial-access and lateral-movement risk.
This framework provides a comprehensive solution for detecting and remediating accounts using default, weak, or exposed credentials across diverse network services, significantly reducing initial-access and lateral-movement attack vectors.

# Key Features
✅ Multi-Protocol Support: SSH, RDP, FTP, HTTP(S), MySQL, PostgreSQL, MSSQL, Redis, MQTT, SNMP, Telnet
✅ Intelligent Rate Limiting: Per-target throttling with exponential backoff
✅ Vault Integration: HashiCorp Vault, Azure Key Vault, CyberArk support
✅ Safe Scanning: Lockout detection, dry-run mode, excluded hosts
✅ Automated Remediation: Password rotation, account lockdown, MFA enablement
✅ Multiple Output Formats: JSON, CSV, HTML reports
✅ CI/CD Ready: GitHub Actions, Jenkins, GitLab CI integration
✅ Production-Ready: Docker deployment, comprehensive logging

# Supported Services
SSH (port 22)
HTTP Basic/Digest Auth (ports 80, 443)
MySQL (port 3306)
FTP (port 21)
Telnet (port 23)
RDP (port 3389)
SNMP (ports 161, 162)
Redis (port 6379)
MQTT (port 1883)

# Key Features
✅ Protocol-specific authentication handlers
✅ Rate limiting & lockout prevention
✅ Vault integration (HashiCorp, Azure Key Vault)
✅ Vendor default credential library
✅ Multiple output formats (JSON, CSV, HTML)
✅ Safe concurrency controls
✅ Dry-run mode

📁 Project Structure
credential-scanner/
├── credential_scanner.py       # Core scanning engine
├── vault_integration.py        # Vault client implementations
├── extended_checkers.py        # Protocol-specific checkers
├── credential_scanner_cli.py   # Command-line interface
├── remediation_scripts.py      # Automated remediation
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Container deployment
├── docker-compose.yml          # Multi-container setup
├── scanner_config.yaml         # Configuration file
├── targets.json                # Target definitions
├── .github/
│   └── workflows/
│       └── credential_scan.yml # CI/CD automation
└── docs/
    ├── RUNBOOK.md              # Operations guide
    ├── REMEDIATION.md          # Remediation playbook
    └── API.md                  # API 


# HTML Report
Opens in browser with: Executive summary
Vulnerability breakdown by risk level
Detailed findings table
Remediation recommendations

📈 Performance Tuning
IssueSolutionSlow scansIncrease max_concurrent to 10-15High CPUDecrease max_concurrent to 3-5Network congestionReduce requests_per_minuteMemory issuesScan targets in batchesRate limitingIncrease lockout_threshold

# Safety Guidelines
Pre-Scan Checklist
 Authorization: Written approval from management/security team
 Scope Validation: Verify all targets are within authorized scope
 Maintenance Window: Schedule during low-traffic periods
 Excluded Hosts: Add critical systems to excluded_hosts
 Dry Run: Test configuration with --dry-run first
 Backup Plan: Document rollback procedures
 Notification: Inform NOC/SOC teams before scanning

# Rate Limiting Best Practices
Environmentmax_concurrentrequests_per_minuteProduction3-55-10Staging5-1010-20Development10-2020-50
Account Lockout Prevention
The scanner implements multiple safety mechanisms:

Exponential Backoff: Delays increase after failed attempts
Per-Target Throttling: Independent rate limits for each host
Lockout Detection: Stops scanning target after threshold
Stop-on-Success: Exits after first valid credential found

# Troubleshooting
Common Issues
1. Connection Timeouts
ERROR: Timeout connecting to 192.168.1.100:22
Solutions:

Increase timeout: scanner.timeout: 30
Check network connectivity: ping 192.168.1.100
Verify firewall rules
Check if service is running: nmap -p22 192.168.1.100

2. Account Lockouts
WARNING: Lockout detected for 192.168.1.100:22
Solutions:

Reduce rate limit: requests_per_minute: 5
Increase lockout threshold: lockout_threshold: 5
Wait for lockout to expire (check system policy)
Manually unlock: faillock --user admin --reset

3. Vault Connection Errors
ERROR: Vault authentication failed
Solutions:

Verify Vault is running: vault status
Check token: echo $VAULT_TOKEN
Test connection: vault kv list secret/
Verify permissions: vault token lookup

4. Missing Dependencies
ImportError: No module named 'paramiko'
Solutions:
bashpip install --upgrade pip
pip install -r requirements.txt
5. Permission Denied
PermissionError: [Errno 13] Permission denied: '/opt/scanner/scan_results'
Solutions:
bashsudo chown -R $USER:$USER /opt/scanner
chmod 755 /opt/scanner
Debug Mode
Enable verbose logging:
bashpython credential_scanner_cli.py \
  --target-file targets.json \
  --debug \
  2>&1 | tee debug.log
Performance Tuning
SymptomAdjustmentSlow scansIncrease max_concurrentHigh CPU usageDecrease max_concurrentNetwork congestionDecrease requests_per_minuteMemory issuesProcess targets in batches

# Security Considerations
Credential Handling
❌ NEVER log plaintext passwords
✅ Store credentials in vault only
✅ Use ephemeral credentials when possible
✅ Encrypt scan results at rest
✅ Secure transport (SSH keys, TLS)

# C. Compliance Checklists
PCI-DSS 8.2.3 Checklist:

 Passwords minimum 7 characters (12+ recommended)
 Both numeric and alphabetic characters
 Change every 90 days
 Cannot reuse last 4 passwords
 Lock account after 6 failed attempts

# D. References
NIST SP 800-63B: Digital Identity Guidelines
CIS Controls v8: Control 4 (Secure Configuration)
OWASP ASVS: V2 Authentication Verification
MITRE ATT&CK: T1078 (Valid Accounts)



