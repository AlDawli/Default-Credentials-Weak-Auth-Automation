#!/usr/bin/env python3
"""
Credential Scanner CLI
Command-line interface with configuration management
"""

import argparse
import asyncio
import json
import logging
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Optional

# Import core scanner components (assuming in same package)
from credential_scanner import (
    CredentialScanner, Target, Credential, ServiceType, ScanResult
)
from vault_integration import CredentialLibrary, HashiCorpVaultClient


class ScannerConfig:
    """Configuration manager for scanner"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.logger = logging.getLogger("ScannerConfig")
    
    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Load configuration from YAML file"""
        default_config = {
            "scanner": {
                "max_concurrent": 5,
                "requests_per_minute": 10,
                "timeout": 10,
                "lockout_threshold": 3
            },
            "vault": {
                "enabled": False,
                "type": "hashicorp",  # hashicorp, azure, cyberark
                "url": "http://localhost:8200",
                "mount_point": "secret"
            },
            "credentials": {
                "vendors": ["cisco", "dell", "generic_iot"],
                "weak_usernames": ["admin", "root", "user"],
                "vault_paths": [],
                "custom": []
            },
            "output": {
                "format": "json",
                "directory": "./scan_results",
                "save_all_attempts": False
            },
            "safety": {
                "dry_run": False,
                "stop_on_lockout": True,
                "excluded_hosts": []
            }
        }
        
        if config_file and Path(config_file).exists():
            try:
                with open(config_file, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge
                    default_config = self._merge_config(default_config, user_config)
                    self.logger.info(f"Loaded configuration from {config_file}")
            except Exception as e:
                self.logger.error(f"Failed to load config: {e}")
        
        return default_config
    
    def _merge_config(self, base: Dict, override: Dict) -> Dict:
        """Recursively merge configuration dictionaries"""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result
    
    def save_config(self, output_file: str):
        """Save current configuration to file"""
        with open(output_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
        self.logger.info(f"Saved configuration to {output_file}")
    
    def get(self, *keys: str, default=None):
        """Get nested configuration value"""
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value


class TargetLoader:
    """Load targets from various sources"""
    
    @staticmethod
    def from_file(target_file: str) -> List[Target]:
        """
        Load targets from JSON/YAML file
        
        Format:
        [
            {"host": "192.168.1.1", "port": 22, "service": "ssh"},
            {"host": "192.168.1.2", "port": 3306, "service": "mysql"}
        ]
        """
        targets = []
        
        with open(target_file, 'r') as f:
            if target_file.endswith('.json'):
                data = json.load(f)
            else:
                data = yaml.safe_load(f)
        
        for item in data:
            try:
                service = ServiceType[item['service'].upper()]
                targets.append(Target(
                    host=item['host'],
                    port=item['port'],
                    service=service,
                    metadata=item.get('metadata', {})
                ))
            except Exception as e:
                logging.error(f"Failed to parse target {item}: {e}")
        
        return targets
    
    @staticmethod
    def from_nmap(nmap_xml: str) -> List[Target]:
        """Parse Nmap XML output to extract targets"""
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            logging.error("xml.etree not available")
            return []
        
        targets = []
        tree = ET.parse(nmap_xml)
        root = tree.getroot()
        
        # Service mapping
        service_map = {
            22: ServiceType.SSH,
            21: ServiceType.FTP,
            23: ServiceType.TELNET,
            3306: ServiceType.MYSQL,
            80: ServiceType.HTTP_BASIC,
            443: ServiceType.HTTP_BASIC
        }
        
        for host in root.findall('.//host'):
            # Get host address
            addr_elem = host.find('.//address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
            
            ip = addr_elem.get('addr')
            
            # Get open ports
            for port in host.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_num = int(port.get('portid'))
                    
                    service_type = service_map.get(port_num)
                    if service_type:
                        targets.append(Target(
                            host=ip,
                            port=port_num,
                            service=service_type
                        ))
        
        return targets
    
    @staticmethod
    def from_cidr(cidr: str, ports: List[int], service: ServiceType) -> List[Target]:
        """Generate targets from CIDR range"""
        try:
            import ipaddress
        except ImportError:
            logging.error("ipaddress module not available")
            return []
        
        targets = []
        network = ipaddress.ip_network(cidr, strict=False)
        
        for ip in network.hosts():
            for port in ports:
                targets.append(Target(
                    host=str(ip),
                    port=port,
                    service=service
                ))
        
        return targets


class ReportGenerator:
    """Generate various report formats"""
    
    @staticmethod
    def generate_json(results: List[ScanResult], output_file: str):
        """Generate JSON report"""
        report = {
            "scan_summary": {
                "total_attempts": len(results),
                "successful": len([r for r in results if r.status.value == "success"]),
                "failed": len([r for r in results if r.status.value == "failed"]),
                "errors": len([r for r in results if r.status.value == "error"])
            },
            "vulnerabilities": [],
            "all_results": []
        }
        
        # Group successful results by target
        vulnerable_targets = {}
        for result in results:
            if result.status.value == "success":
                target_id = result.target.identifier
                if target_id not in vulnerable_targets:
                    vulnerable_targets[target_id] = {
                        "target": {
                            "host": result.target.host,
                            "port": result.target.port,
                            "service": result.target.service.value
                        },
                        "credentials": []
                    }
                
                vulnerable_targets[target_id]["credentials"].append({
                    "username": result.credential.username,
                    "source": result.credential.source,
                    "risk_level": result.credential.risk_level,
                    "timestamp": result.timestamp
                })
        
        report["vulnerabilities"] = list(vulnerable_targets.values())
        report["all_results"] = [r.to_dict() for r in results]
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    @staticmethod
    def generate_csv(results: List[ScanResult], output_file: str):
        """Generate CSV report"""
        import csv
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Host', 'Port', 'Service', 'Username', 'Status',
                'Risk Level', 'Source', 'Timestamp', 'Response Time'
            ])
            
            for result in results:
                if result.status.value == "success":
                    writer.writerow([
                        result.target.host,
                        result.target.port,
                        result.target.service.value,
                        result.credential.username,
                        result.status.value,
                        result.credential.risk_level,
                        result.credential.source,
                        result.timestamp,
                        f"{result.response_time:.2f}"
                    ])
    
    @staticmethod
    def generate_html(results: List[ScanResult], output_file: str):
        """Generate HTML report"""
        successful = [r for r in results if r.status.value == "success"]
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Credential Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Default Credential Scan Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total Scans:</strong> {len(results)}</p>
        <p><strong>Vulnerable Systems:</strong> <span class="critical">{len(successful)}</span></p>
        <p><strong>Scan Date:</strong> {results[0].timestamp if results else 'N/A'}</p>
    </div>
    
    <h2>Vulnerable Systems</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
            <th>Username</th>
            <th>Risk Level</th>
            <th>Source</th>
        </tr>
"""
        
        for result in successful:
            risk_class = result.credential.risk_level
            html += f"""
        <tr>
            <td>{result.target.host}</td>
            <td>{result.target.port}</td>
            <td>{result.target.service.value}</td>
            <td>{result.credential.username}</td>
            <td class="{risk_class}">{result.credential.risk_level}</td>
            <td>{result.credential.source}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html)


async def run_scan(args, config: ScannerConfig):
    """Execute credential scan"""
    logger = logging.getLogger("CredScan")
    
    # Load targets
    if args.target_file:
        targets = TargetLoader.from_file(args.target_file)
    elif args.nmap_xml:
        targets = TargetLoader.from_nmap(args.nmap_xml)
    elif args.cidr:
        service = ServiceType[args.service.upper()]
        ports = [int(p) for p in args.ports.split(',')]
        targets = TargetLoader.from_cidr(args.cidr, ports, service)
    else:
        logger.error("No target source specified")
        return
    
    # Filter excluded hosts
    excluded = set(config.get("safety", "excluded_hosts", default=[]))
    targets = [t for t in targets if t.host not in excluded]
    
    logger.info(f"Loaded {len(targets)} targets")
    
    # Build credential set
    library = CredentialLibrary()
    cred_config = config.get("credentials")
    credential_sets = library.build_credential_set(cred_config)
    
    # Convert to scanner format
    credentials = [
        Credential(
            username=cs.username,
            password=cs.password,
            source=cs.source,
            risk_level=cs.risk_level
        )
        for cs in credential_sets
    ]
    
    logger.info(f"Built credential set: {len(credentials)} credentials")
    
    # Dry run check
    if config.get("safety", "dry_run"):
        logger.info("DRY RUN MODE - No actual connections will be made")
        logger.info(f"Would scan {len(targets)} targets with {len(credentials)} credentials")
        return
    
    # Initialize scanner
    scanner = CredentialScanner(
        max_concurrent=config.get("scanner", "max_concurrent"),
        requests_per_minute=config.get("scanner", "requests_per_minute")
    )
    
    # Execute scan
    logger.info("Starting credential scan...")
    results = await scanner.scan_all(targets, credentials)
    
    # Generate reports
    output_dir = Path(config.get("output", "directory"))
    output_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = results[0].timestamp.split('T')[0] if results else "unknown"
    
    # JSON report
    json_file = output_dir / f"scan_results_{timestamp}.json"
    ReportGenerator.generate_json(results, str(json_file))
    logger.info(f"JSON report: {json_file}")
    
    # CSV report
    csv_file = output_dir / f"scan_results_{timestamp}.csv"
    ReportGenerator.generate_csv(results, str(csv_file))
    logger.info(f"CSV report: {csv_file}")
    
    # HTML report
    html_file = output_dir / f"scan_report_{timestamp}.html"
    ReportGenerator.generate_html(results, str(html_file))
    logger.info(f"HTML report: {html_file}")
    
    # Print summary
    successful = [r for r in results if r.status.value == "success"]
    print(f"\n{'='*60}")
    print(f"SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"Total attempts: {len(results)}")
    print(f"Vulnerable systems: {len(successful)}")
    print(f"Unique targets compromised: {len(set(r.target.identifier for r in successful))}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Default Credential & Weak Auth Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Target specification
    target_group = parser.add_argument_group("Target Specification")
    target_group.add_argument('-t', '--target-file', help='Target list file (JSON/YAML)')
    target_group.add_argument('-n', '--nmap-xml', help='Nmap XML output file')
    target_group.add_argument('-c', '--cidr', help='CIDR range (e.g., 192.168.1.0/24)')
    target_group.add_argument('-p', '--ports', help='Comma-separated ports (with --cidr)')
    target_group.add_argument('-s', '--service', help='Service type (with --cidr)')
    
    # Configuration
    parser.add_argument('--config', help='Configuration file (YAML)', default='scanner_config.yaml')
    parser.add_argument('--generate-config', action='store_true', help='Generate sample config')
    
    # Logging
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose logging')
    parser.add_argument('--debug', action='store_true', help='Debug logging')
    
    # Safety
    parser.add_argument('--dry-run', action='store_true', help='Dry run (no actual connections)')
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Generate config
    if args.generate_config:
        config = ScannerConfig()
        config.save_config('scanner_config.yaml')
        print("Generated scanner_config.yaml")
        return
    
    # Load configuration
    config = ScannerConfig(args.config if Path(args.config).exists() else None)
    
    # Override with CLI args
    if args.dry_run:
        config.config['safety']['dry_run'] = True
    
    # Run scan
    try:
        asyncio.run(run_scan(args, config))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Scan failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
