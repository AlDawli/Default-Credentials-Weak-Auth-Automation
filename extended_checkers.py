#!/usr/bin/env python3
"""
Extended Protocol Checkers
Additional service-specific credential validators for FTP, Telnet, RDP, SNMP, Redis, MQTT
"""

import asyncio
import logging
import socket
import time
from typing import Optional

# Import base classes
from credential_scanner import ServiceChecker, Target, Credential, ScanResult, ScanStatus


class FTPChecker(ServiceChecker):
    """FTP credential checker using ftplib"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            from ftplib import FTP, error_perm
            
            ftp = FTP()
            
            # Run in executor to avoid blocking
            loop = asyncio.get_event_loop()
            
            # Connect
            await loop.run_in_executor(
                None,
                lambda: ftp.connect(target.host, target.port, timeout=self.timeout)
            )
            
            # Attempt login
            await loop.run_in_executor(
                None,
                lambda: ftp.login(credential.username, credential.password)
            )
            
            # Get server info
            welcome = ftp.getwelcome()
            
            response_time = time.time() - start_time
            
            # Close connection
            await loop.run_in_executor(None, ftp.quit)
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"welcome_message": welcome}
            )
            
        except error_perm as e:
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


class TelnetChecker(ServiceChecker):
    """Telnet credential checker using telnetlib"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            import telnetlib
            
            loop = asyncio.get_event_loop()
            
            # Create connection
            tn = telnetlib.Telnet()
            await loop.run_in_executor(
                None,
                lambda: tn.open(target.host, target.port, timeout=self.timeout)
            )
            
            # Wait for login prompt (common patterns)
            await loop.run_in_executor(
                None,
                lambda: tn.read_until(b"login: ", timeout=5)
            )
            
            # Send username
            await loop.run_in_executor(
                None,
                lambda: tn.write(credential.username.encode('ascii') + b"\n")
            )
            
            # Wait for password prompt
            await loop.run_in_executor(
                None,
                lambda: tn.read_until(b"Password: ", timeout=5)
            )
            
            # Send password
            await loop.run_in_executor(
                None,
                lambda: tn.write(credential.password.encode('ascii') + b"\n")
            )
            
            # Read response
            response = await loop.run_in_executor(
                None,
                lambda: tn.read_some()
            )
            
            response_time = time.time() - start_time
            
            # Check for successful login indicators
            success_indicators = [b"$", b"#", b">", b"Welcome", b"Last login"]
            failure_indicators = [b"Login incorrect", b"Authentication failed", b"Access denied"]
            
            response_lower = response.lower()
            
            if any(indicator.lower() in response_lower for indicator in failure_indicators):
                status = ScanStatus.FAILED
                error_msg = "Authentication failed"
            elif any(indicator.lower() in response_lower for indicator in success_indicators):
                status = ScanStatus.SUCCESS
                error_msg = None
            else:
                # Ambiguous response
                status = ScanStatus.ERROR
                error_msg = "Unable to determine authentication result"
            
            # Close connection
            await loop.run_in_executor(None, tn.close)
            
            return self._create_result(
                target, credential, status, response_time,
                error_message=error_msg,
                metadata={"response_snippet": response.decode('ascii', errors='ignore')[:100]}
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )


class RDPChecker(ServiceChecker):
    """
    RDP credential checker using socket-based NLA check
    Note: Full RDP authentication requires pyrdp or rdesktop wrapper
    """
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            # Basic socket check (simplified version)
            # For production, use pyrdp or call rdesktop/xfreerdp subprocess
            
            loop = asyncio.get_event_loop()
            
            # Attempt socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            await loop.run_in_executor(
                None,
                lambda: sock.connect((target.host, target.port))
            )
            
            # Send X.224 Connection Request (RDP handshake start)
            x224_conn_req = b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00'
            
            await loop.run_in_executor(None, lambda: sock.send(x224_conn_req))
            
            # Read response
            response = await loop.run_in_executor(None, lambda: sock.recv(1024))
            
            response_time = time.time() - start_time
            sock.close()
            
            # Check if RDP is available (connection confirmed)
            if len(response) > 0 and response[0:2] == b'\x03\x00':
                # RDP is available, but we can't fully test creds without full RDP client
                return self._create_result(
                    target, credential, ScanStatus.ERROR, response_time,
                    error_message="RDP available but full authentication test not implemented",
                    metadata={"rdp_available": True, "note": "Use pyrdp or subprocess wrapper for full test"}
                )
            else:
                return self._create_result(
                    target, credential, ScanStatus.ERROR, response_time,
                    error_message="Invalid RDP response"
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )


class SNMPChecker(ServiceChecker):
    """SNMP community string checker using pysnmp"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
            
            loop = asyncio.get_event_loop()
            
            # SNMP uses "community strings" instead of username/password
            # credential.password is the community string
            community = credential.password
            
            # Attempt SNMP GET (system description)
            def snmp_get():
                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(
                        SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((target.host, target.port), timeout=self.timeout),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
                    )
                )
                
                if errorIndication:
                    raise Exception(str(errorIndication))
                elif errorStatus:
                    raise Exception(f"SNMP error: {errorStatus.prettyPrint()}")
                
                return varBinds
            
            varBinds = await loop.run_in_executor(None, snmp_get)
            
            response_time = time.time() - start_time
            
            # Extract system description
            sys_descr = str(varBinds[0][1]) if varBinds else "unknown"
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"community": community, "system_description": sys_descr}
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            
            if "timeout" in str(e).lower() or "no response" in str(e).lower():
                status = ScanStatus.FAILED
            else:
                status = ScanStatus.ERROR
            
            return self._create_result(
                target, credential, status, response_time,
                error_message=str(e)
            )


class RedisChecker(ServiceChecker):
    """Redis credential checker using redis-py"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            import redis
            
            loop = asyncio.get_event_loop()
            
            # Connect to Redis
            client = redis.Redis(
                host=target.host,
                port=target.port,
                password=credential.password,
                socket_timeout=self.timeout,
                decode_responses=True
            )
            
            # Test authentication with PING
            await loop.run_in_executor(None, client.ping)
            
            # Get server info
            info = await loop.run_in_executor(None, client.info, 'server')
            
            response_time = time.time() - start_time
            
            # Close connection
            await loop.run_in_executor(None, client.close)
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={
                    "redis_version": info.get('redis_version', 'unknown'),
                    "os": info.get('os', 'unknown')
                }
            )
            
        except redis.AuthenticationError:
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


class MQTTChecker(ServiceChecker):
    """MQTT credential checker using paho-mqtt"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        
        try:
            import paho.mqtt.client as mqtt
            
            auth_result = {"success": False, "error": None}
            connect_event = asyncio.Event()
            
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    auth_result["success"] = True
                else:
                    auth_result["error"] = f"Connection failed with code {rc}"
                connect_event.set()
            
            def on_disconnect(client, userdata, rc):
                if not connect_event.is_set():
                    auth_result["error"] = f"Disconnected with code {rc}"
                    connect_event.set()
            
            # Create MQTT client
            client = mqtt.Client()
            client.username_pw_set(credential.username, credential.password)
            client.on_connect = on_connect
            client.on_disconnect = on_disconnect
            
            # Connect
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: client.connect(target.host, target.port, keepalive=self.timeout)
            )
            
            # Start network loop in background
            await loop.run_in_executor(None, lambda: client.loop_start())
            
            # Wait for connection result
            try:
                await asyncio.wait_for(connect_event.wait(), timeout=self.timeout)
            except asyncio.TimeoutError:
                auth_result["error"] = "Connection timeout"
            
            response_time = time.time() - start_time
            
            # Stop loop and disconnect
            await loop.run_in_executor(None, lambda: client.loop_stop())
            await loop.run_in_executor(None, lambda: client.disconnect())
            
            if auth_result["success"]:
                return self._create_result(
                    target, credential, ScanStatus.SUCCESS, response_time,
                    metadata={"protocol": "MQTT"}
                )
            else:
                return self._create_result(
                    target, credential, ScanStatus.FAILED, response_time,
                    error_message=auth_result["error"] or "Authentication failed"
                )
            
        except Exception as e:
            response_time = time.time() - start_time
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=str(e)
            )


class PostgreSQLChecker(ServiceChecker):
    """PostgreSQL credential checker using psycopg2"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        connection = None
        
        try:
            import psycopg2
            
            loop = asyncio.get_event_loop()
            
            # Connect to PostgreSQL
            connection = await loop.run_in_executor(
                None,
                lambda: psycopg2.connect(
                    host=target.host,
                    port=target.port,
                    user=credential.username,
                    password=credential.password,
                    connect_timeout=self.timeout,
                    database='postgres'  # Default database
                )
            )
            
            # Get version
            cursor = connection.cursor()
            await loop.run_in_executor(None, cursor.execute, "SELECT version()")
            version = (await loop.run_in_executor(None, cursor.fetchone))[0]
            cursor.close()
            
            response_time = time.time() - start_time
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"version": version}
            )
            
        except psycopg2.OperationalError as e:
            response_time = time.time() - start_time
            
            error_str = str(e)
            if "authentication failed" in error_str.lower() or "password" in error_str.lower():
                return self._create_result(
                    target, credential, ScanStatus.FAILED, response_time,
                    error_message="Authentication failed"
                )
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=error_str
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


class MSSQLChecker(ServiceChecker):
    """Microsoft SQL Server credential checker using pymssql"""
    
    async def check_credential(self, target: Target, credential: Credential) -> ScanResult:
        start_time = time.time()
        connection = None
        
        try:
            import pymssql
            
            loop = asyncio.get_event_loop()
            
            # Connect to MSSQL
            connection = await loop.run_in_executor(
                None,
                lambda: pymssql.connect(
                    server=target.host,
                    port=target.port,
                    user=credential.username,
                    password=credential.password,
                    timeout=self.timeout
                )
            )
            
            # Get version
            cursor = connection.cursor()
            await loop.run_in_executor(None, cursor.execute, "SELECT @@VERSION")
            version = (await loop.run_in_executor(None, cursor.fetchone))[0]
            cursor.close()
            
            response_time = time.time() - start_time
            
            return self._create_result(
                target, credential, ScanStatus.SUCCESS, response_time,
                metadata={"version": version}
            )
            
        except pymssql.OperationalError as e:
            response_time = time.time() - start_time
            
            error_str = str(e)
            if "login failed" in error_str.lower():
                return self._create_result(
                    target, credential, ScanStatus.FAILED, response_time,
                    error_message="Authentication failed"
                )
            return self._create_result(
                target, credential, ScanStatus.ERROR, response_time,
                error_message=error_str
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


# Update the main scanner to include these checkers
def register_extended_checkers(scanner):
    """
    Register extended protocol checkers with the scanner
    
    Usage:
        scanner = CredentialScanner()
        register_extended_checkers(scanner)
    """
    from credential_scanner import ServiceType
    
    scanner.checkers[ServiceType.FTP] = FTPChecker()
    scanner.checkers[ServiceType.TELNET] = TelnetChecker()
    scanner.checkers[ServiceType.RDP] = RDPChecker()
    scanner.checkers[ServiceType.SNMP] = SNMPChecker()
    scanner.checkers[ServiceType.REDIS] = RedisChecker()
    scanner.checkers[ServiceType.MQTT] = MQTTChecker()
    
    # Add additional database checkers
    # Note: PostgreSQL and MSSQL ServiceTypes need to be added to the enum
    # scanner.checkers[ServiceType.POSTGRESQL] = PostgreSQLChecker()
    # scanner.checkers[ServiceType.MSSQL] = MSSQLChecker()


# Example usage
async def test_extended_checkers():
    """Test extended protocol checkers"""
    from credential_scanner import CredentialScanner, Target, Credential, ServiceType
    
    logging.basicConfig(level=logging.INFO)
    
    # Example targets
    targets = [
        Target(host="192.168.1.100", port=21, service=ServiceType.FTP),
        Target(host="192.168.1.101", port=23, service=ServiceType.TELNET),
        Target(host="192.168.1.102", port=161, service=ServiceType.SNMP),
        Target(host="192.168.1.103", port=6379, service=ServiceType.REDIS),
        Target(host="192.168.1.104", port=1883, service=ServiceType.MQTT)
    ]
    
    # Example credentials
    credentials = [
        Credential("admin", "admin", source="test"),
        Credential("root", "password", source="test"),
        Credential("public", "public", source="snmp_community"),  # For SNMP
    ]
    
    # Initialize scanner
    scanner = CredentialScanner(max_concurrent=3, requests_per_minute=10)
    
    # Register extended checkers
    register_extended_checkers(scanner)
    
    # Run scan
    results = await scanner.scan_all(targets, credentials)
    
    # Print results
    for result in results:
        if result.status.value == "success":
            print(f"✓ {result.target.identifier} - {result.credential.username}")


if __name__ == "__main__":
    asyncio.run(test_extended_checkers())
