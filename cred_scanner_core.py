#!/usr/bin/env python3
"""
Default-Credentials & Weak-Auth Scanner
Core scanning engine with protocol-specific handlers and safety controls
"""

import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import List, Dict, Optional, Set
import hashlib

# Third-party imports (install via: pip install paramiko pymysql pysmb pysnmp requests)
try:
    import paramiko
    import pymysql
    import requests
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
except ImportError as e:
    print(f"Missing dependency: {e}. Install via: pip install paramiko pymysql requests")
    raise


class ServiceType(Enum):
    """Supported service types"""
    SSH = "ssh"
    HTTP_BASIC = "http_basic"
    HTTP_DIGEST = "http_digest"
    MYSQL = "mysql"
    FTP = "ftp"
    TELNET = "telnet"
    RDP = "rdp"
    SNMP = "snmp"
    REDIS = "redis"
    MQTT = "mqtt"


class ScanStatus(Enum):
    """Scan result status"""
    SUCCESS = "success"
    FAILED = "failed"
    ERROR = "error"
    THROTTLED = "throttled"
    LOCKOUT_DETECTED = "lockout_detected"


@dataclass
class Target:
    """Target host configuration"""
    host: str
    port: int
    service: ServiceType
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def identifier(self) -> str:
        """Unique target identifier"""
        return f"{self.host}:{self.port}:{self.service.value}"


@dataclass
class Credential:
    """Credential pair with metadata"""
    username: str
    password: str
    source: str = "manual"  # vendor_default, common_weak, test_account
    risk_level: str = "high"  # high, medium, low
    
    @property
    def hash_id(self) -> str:
        """Non-reversible credential identifier for logging"""
        raw = f"{self.username}:{self.password}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Individual scan attempt result"""
    target: Target
    credential: Credential
    status: ScanStatus
    timestamp: str
    response_time: float
    error_message: Optional[str] = None
    metadata: Dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON export"""
        return {
            "target": {
                "host": self.target.host,
                "port": self.target.port,
                "service": self.target.service.value,
                "metadata": self.target.metadata
            },
            "credential": {
                "username": self.credential.username,
                "source": self.credential.source,
                "risk_level": self.credential.risk_level,
                "hash_id": self.credential.hash_id
            },
            "status": self.status.value,
            "timestamp": self.timestamp,
            "response_time": response_time,
            "error_message": self.error_message,
            "metadata": self.metadata
        }


class RateLimiter:
    """Per-target rate limiting with exponential backoff"""
    
    def __init__(self, requests_per_minute: int = 10, lockout_threshold: int = 3):
        self.requests_per_minute = requests_per_minute
        self.lockout_threshold = lockout_threshold
        self.target_state: Dict[str, Dict] = {}
        self.lock = asyncio.Lock()
    
    async def acquire(self, target_id: str) -> bool:
        """Acquire permission to attempt connection"""
        async with self.lock:
            now = time.time()
            
            if target_id not in self.target_state:
                self.target_state[target_id] = {
                    "attempts": [],
                    "failures": 0,
                    "locked_until": 0,
                    "backoff_seconds": 1
                }
            
            state = self.target_state[target_id]
            
            # Check lockout
            if now < state["locked_until"]:
                return False
            
            # Check lockout threshold
            if state["failures"] >= self.lockout_threshold:
                state["locked_until"] = now + state["backoff_seconds"]
                state["backoff_seconds"] = min(state["backoff_seconds"] * 2, 300)  # Max 5 min
                return False
            
            # Clean old attempts
            cutoff = now - 60
            state["attempts"] = [t for t in state["attempts"] if t > cutoff]
            
            # Check rate limit
            if len(state["attempts"]) >= self.requests_per_minute:
                return False
            
            state["attempts"].append(now)
            return True
    
    async def record_result(self, target_id: str, success: bool):
        """Record attempt result for adaptive throttling"""
        async with self.lock:
            if target_id in self.target_state:
                if success:
                    self.target_state[target_id]["failures"] = 0
                    self.target_state[target_id]["backoff_seconds"] = 1
                else:
                    self.target_state[target_id]["failures"] += 1


class ServiceChecker(ABC):
    """Abstract base class for service-specific credential checkers"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        """Attempt authentication and return result"""
        pass
    
    def _create_result(self, target: Target, credential: Credential, 
                      status: ScanStatus, response_time: float,
                      error_message: Optional[str] = None,
                      metadata: Optional[Dict] = None) -> ScanResult:
        """Helper to create scan result"""
        return ScanResult(
            target=target,
            credential=credential,
            status=status,
            timestamp=datetime.utcnow().isoformat(),
            response_time=response_time,
            error_message=error_message,
            metadata=metadata or {}
        )


class SSHChecker(ServiceChecker):
    """SSH credential checker using paramiko"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: client.connect(
                    hostname=target.host,
                    port=target.port,
                    username=credential.username,
                    password=credential.password,
                    timeout=self.timeout,
                    look_for_keys=False,
                    allow_agent=False
                )
            )
            
            # Get basic info without executing commands (safer)
            transport = client.get_transport()
            server_banner = transport.remote_version if transport else "unknown"
            
            response_time = time.time() - start_time
            
            # Immediately close connection
            client.close()
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"server_banner": server_banner}
            )
            
        except paramiko.AuthenticationException:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.FAILED, response_time,
                error_message="Authentication failed"
            )
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )
        finally:
            try:
                client.close()
            except:
                pass


class HTTPAuthChecker(ServiceChecker):
    """HTTP Basic/Digest authentication checker"""
    
    def __init__(self, timeout: int = 10, auth_type: str = "basic"):
        super().__init__(timeout)
        self.auth_type = auth_type
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        url = f"http://{target.host}:{target.port}"
        if target.metadata.get("path"):
            url += target.metadata["path"]
        
        try:
            auth = HTTPBasicAuth(credential.username, credential.password) \
                   if self.auth_type == "basic" else \
                   HTTPDigestAuth(credential.username, credential.password)
            
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(url, auth=auth, timeout=self.timeout, verify=False)
            )
            
            response_time = time.time() - start_time
            
            if response.status_code == 200:
                return self._create_result(
                    target, credential, ScanStatus.SUCCESS, response_time,
                    metadata={"status_code": 200, "server": response.headers.get("Server", "unknown")}
                )
            elif response.status_code == 401:
                return self._create_result(
                    target, credential, ScanStatus.FAILED, response_time,
                    error_message="Authentication failed"
                )
            else:
                return self._create_result(
                    target, credential, ScanStatus.ERROR, response_time,
                    error_message=f"Unexpected status: {response.status_code}"
                )
                
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )


class MySQLChecker(ServiceChecker):
    """MySQL credential checker"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        connection = None
        
        try:
            loop = asyncio.get_event_loop()
            connection = await loop.run_in_executor(
                None,
                lambda: pymysql.connect(
                    host=target.host,
                    port=target.port,
                    user=credential.username,
                    password=credential.password,
                    connect_timeout=self.timeout
                )
            )
            
            # Get server version without executing queries
            cursor = connection.cursor()
            await loop.run_in_executor(None, cursor.execute, "SELECT VERSION()")
            version = (await loop.run_in_executor(None, cursor.fetchone))[0]
            cursor.close()
            
            response_time = time.time() - start_time
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"version": version}
            )
            
        except pymysql.OperationalError as e:
            response_time = time.time() - start_time
            if "Access denied" in str(e):
                return self._create_result(
                    target, credential, ScanStatus.FAILED, response_time,
                    error_message="Authentication failed"
                )
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )
        finally:
            if connection:
                try:
                    connection.close()
                except:
                    pass


class CredentialScanner:
    """Main scanner orchestrator"""
    
    def __init__(self, max_concurrent: int = 5, requests_per_minute: int = 10):
        self.max_concurrent = max_concurrent
        self.rate_limiter = RateLimiter(requests_per_minute=requests_per_minute)
        self.results: List[ScanResult] = []
        self.logger = logging.getLogger("CredentialScanner")
        
        # Initialize service checkers
        self.checkers = {
            ServiceType.SSH: SSHChecker(),
            ServiceType.HTTP_BASIC: HTTPAuthChecker(auth_type="basic"),
            ServiceType.HTTP_DIGEST: HTTPAuthChecker(auth_type="digest"),
            ServiceType.MYSQL: MySQLChecker()
        }
    
    async def scan_target(self, target: Target, credentials: List[Credential]) -> List[ScanResult]:
        """Scan a single target with multiple credentials"""
        target_results = []
        
        for credential in credentials:
            # Rate limiting
            max_retries = 3
            for retry in range(max_retries):
                if await self.rate_limiter.acquire(target.identifier):
                    break
                await asyncio.sleep(2 ** retry)  # Exponential backoff
            else:
                # Max retries exceeded
                result = ScanResult(
                    target=target,
                    credential=credential,
                    status=ScanStatus.THROTTLED,
                    timestamp=datetime.utcnow().isoformat(),
                    response_time=0,
                    error_message="Rate limit exceeded"
                )
                target_results.append(result)
                continue
            
            # Get appropriate checker
            checker = self.checkers.get(target.service)
            if not checker:
                self.logger.warning(f"No checker for service: {target.service}")
                continue
            
            # Perform check
            try:
                result = await checker.check_credential(target, credential)
                target_results.append(result)
                
                # Record result for adaptive throttling
                await self.rate_limiter.record_result(
                    target.identifier,
                    result.status == ScanStatus.SUCCESS
                )
                
                # Stop on first success to avoid lockout
                if result.status == ScanStatus.SUCCESS:
                    self.logger.info(f"✓ Valid credential found for {target.identifier}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Error scanning {target.identifier}: {e}")
        
        return target_results
    
    async def scan_all(self, targets: List[Target], credentials: List[Credential]) -> List[ScanResult]:
        """Scan multiple targets concurrently with credential sets"""
        self.logger.info(f"Starting scan: {len(targets)} targets, {len(credentials)} credentials")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_scan(target):
            async with semaphore:
                return await self.scan_target(target, credentials)
        
        # Execute scans
        tasks = [bounded_scan(target) for target in targets]
        results_lists = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results
        all_results = []
        for results in results_lists:
            if isinstance(results, Exception):
                self.logger.error(f"Task failed: {results}")
                continue
            all_results.extend(results)
        
        self.results = all_results
        return all_results
    
    def generate_report(self, output_file: str = "scan_results.json"):
        """Generate JSON report of findings"""
        report = {
            "scan_metadata": {
                "timestamp": datetime.utcnow().isoformat(),
                "total_attempts": len(self.results),
                "successful_auths": len([r for r in self.results if r.status == ScanStatus.SUCCESS])
            },
            "findings": [r.to_dict() for r in self.results if r.status == ScanStatus.SUCCESS],
            "all_results": [r.to_dict() for r in self.results]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report written to {output_file}")
        return report


# Example usage
async def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Define targets
    targets = [
        Target(host="192.168.1.100", port=22, service=ServiceType.SSH),
        Target(host="192.168.1.101", port=3306, service=ServiceType.MYSQL),
        Target(host="192.168.1.102", port=80, service=ServiceType.HTTP_BASIC, 
               metadata={"path": "/admin"})
    ]
    
    # Define credentials (vendor defaults, weak passwords)
    credentials = [
        Credential("admin", "admin", source="vendor_default", risk_level="critical"),
        Credential("root", "root", source="vendor_default", risk_level="critical"),
        Credential("admin", "password", source="common_weak", risk_level="high"),
        Credential("admin", "12345", source="common_weak", risk_level="high")
    ]
    
    # Initialize scanner
    scanner = CredentialScanner(max_concurrent=3, requests_per_minute=10)
    
    # Run scan
    results = await scanner.scan_all(targets, credentials)
    
    # Generate report
    scanner.generate_report("credential_scan_results.json")
    
    # Print summary
    successful = [r for r in results if r.status == ScanStatus.SUCCESS]
    print(f"\n=== SCAN SUMMARY ===")
    print(f"Total attempts: {len(results)}")
    print(f"Successful authentications: {len(successful)}")
    print(f"Vulnerable targets: {len(set(r.target.identifier for r in successful))}")


if __name__ == "__main__":
    asyncio.run(main())
