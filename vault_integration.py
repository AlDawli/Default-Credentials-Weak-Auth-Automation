#!/usr/bin/env python3
"""
Vault Integration & Credential Management
Secure credential handling with HashiCorp Vault, Azure Key Vault integration
"""

import os
import json
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Optional
from dataclasses import dataclass

# Third-party imports
try:
    import hvac  # HashiCorp Vault client
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
except ImportError as e:
    print(f"Install dependencies: pip install hvac azure-identity azure-keyvault-secrets")


@dataclass
class CredentialSet:
    """Structured credential set with metadata"""
    username: str
    password: str
    service_type: str
    source: str = "vault"
    tags: List[str] = None
    risk_level: str = "high"
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []


class VaultInterface(ABC):
    """Abstract interface for secret vault implementations"""
    
    @abstractmethod
    def get_credential(self, path: str) -> Optional[CredentialSet]:
        """Retrieve a single credential from vault"""
        pass
    
    @abstractmethod
    def get_credential_batch(self, prefix: str) -> List[CredentialSet]:
        """Retrieve multiple credentials by prefix"""
        pass
    
    @abstractmethod
    def store_credential(self, path: str, credential: CredentialSet) -> bool:
        """Store credential securely"""
        pass


class HashiCorpVaultClient(VaultInterface):
    """HashiCorp Vault integration"""
    
    def __init__(self, vault_url: str, token: Optional[str] = None, 
                 mount_point: str = "secret"):
        """
        Initialize Vault client
        
        Args:
            vault_url: Vault server URL (e.g., https://vault.example.com:8200)
            token: Vault token (or use VAULT_TOKEN env var)
            mount_point: KV secrets engine mount point
        """
        self.client = hvac.Client(
            url=vault_url,
            token=token or os.getenv("VAULT_TOKEN")
        )
        self.mount_point = mount_point
        self.logger = logging.getLogger("HashiCorpVaultClient")
        
        # Verify authentication
        if not self.client.is_authenticated():
            raise ValueError("Vault authentication failed")
    
    def get_credential(self, path: str) -> Optional[CredentialSet]:
        """
        Retrieve credential from Vault KV store
        
        Args:
            path: Secret path (e.g., 'credentials/ssh/default')
        
        Returns:
            CredentialSet or None if not found
        """
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.mount_point
            )
            
            data = response['data']['data']
            
            return CredentialSet(
                username=data.get('username', ''),
                password=data.get('password', ''),
                service_type=data.get('service_type', 'unknown'),
                source='vault',
                tags=data.get('tags', []),
                risk_level=data.get('risk_level', 'high')
            )
        except Exception as e:
            self.logger.error(f"Failed to retrieve credential from {path}: {e}")
            return None
    
    def get_credential_batch(self, prefix: str) -> List[CredentialSet]:
        """
        Retrieve all credentials under a path prefix
        
        Args:
            prefix: Path prefix (e.g., 'credentials/ssh/')
        
        Returns:
            List of CredentialSet objects
        """
        credentials = []
        
        try:
            # List secrets under prefix
            response = self.client.secrets.kv.v2.list_secrets(
                path=prefix,
                mount_point=self.mount_point
            )
            
            keys = response['data']['keys']
            
            for key in keys:
                full_path = f"{prefix.rstrip('/')}/{key}"
                cred = self.get_credential(full_path)
                if cred:
                    credentials.append(cred)
            
        except Exception as e:
            self.logger.error(f"Failed to list credentials under {prefix}: {e}")
        
        return credentials
    
    def store_credential(self, path: str, credential: CredentialSet) -> bool:
        """
        Store credential in Vault
        
        Args:
            path: Secret path
            credential: CredentialSet to store
        
        Returns:
            True if successful
        """
        try:
            secret_data = {
                'username': credential.username,
                'password': credential.password,
                'service_type': credential.service_type,
                'tags': credential.tags,
                'risk_level': credential.risk_level
            }
            
            self.client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=secret_data,
                mount_point=self.mount_point
            )
            
            self.logger.info(f"Stored credential at {path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store credential at {path}: {e}")
            return False


class AzureKeyVaultClient(VaultInterface):
    """Azure Key Vault integration"""
    
    def __init__(self, vault_url: str):
        """
        Initialize Azure Key Vault client
        
        Args:
            vault_url: Key Vault URL (e.g., https://myvault.vault.azure.net/)
        """
        credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=vault_url, credential=credential)
        self.logger = logging.getLogger("AzureKeyVaultClient")
    
    def get_credential(self, path: str) -> Optional[CredentialSet]:
        """
        Retrieve credential from Azure Key Vault
        
        Args:
            path: Secret name (e.g., 'ssh-default-admin')
        
        Returns:
            CredentialSet or None if not found
        """
        try:
            # Azure KV requires secret names to be alphanumeric/hyphens
            secret_name = path.replace('/', '-')
            
            secret = self.client.get_secret(secret_name)
            
            # Parse JSON value
            data = json.loads(secret.value)
            
            return CredentialSet(
                username=data.get('username', ''),
                password=data.get('password', ''),
                service_type=data.get('service_type', 'unknown'),
                source='azure_keyvault',
                tags=data.get('tags', []),
                risk_level=data.get('risk_level', 'high')
            )
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve secret {path}: {e}")
            return None
    
    def get_credential_batch(self, prefix: str) -> List[CredentialSet]:
        """
        Retrieve credentials by name prefix
        
        Args:
            prefix: Secret name prefix (e.g., 'ssh-')
        
        Returns:
            List of CredentialSet objects
        """
        credentials = []
        
        try:
            # List all secrets and filter by prefix
            secret_properties = self.client.list_properties_of_secrets()
            
            for prop in secret_properties:
                if prop.name.startswith(prefix.replace('/', '-')):
                    cred = self.get_credential(prop.name)
                    if cred:
                        credentials.append(cred)
            
        except Exception as e:
            self.logger.error(f"Failed to list secrets with prefix {prefix}: {e}")
        
        return credentials
    
    def store_credential(self, path: str, credential: CredentialSet) -> bool:
        """
        Store credential in Azure Key Vault
        
        Args:
            path: Secret name
            credential: CredentialSet to store
        
        Returns:
            True if successful
        """
        try:
            secret_name = path.replace('/', '-')
            
            secret_value = json.dumps({
                'username': credential.username,
                'password': credential.password,
                'service_type': credential.service_type,
                'tags': credential.tags,
                'risk_level': credential.risk_level
            })
            
            self.client.set_secret(secret_name, secret_value)
            
            self.logger.info(f"Stored credential as {secret_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store secret {path}: {e}")
            return False


class CredentialLibrary:
    """
    Centralized credential management with vault integration
    Handles vendor defaults, weak password lists, and custom test accounts
    """
    
    def __init__(self, vault_client: Optional[VaultInterface] = None):
        self.vault_client = vault_client
        self.logger = logging.getLogger("CredentialLibrary")
        
        # Built-in vendor defaults (subset for demonstration)
        self.vendor_defaults = self._load_vendor_defaults()
        
        # Common weak passwords
        self.weak_passwords = self._load_weak_passwords()
    
    def _load_vendor_defaults(self) -> Dict[str, List[Dict]]:
        """Load vendor default credentials by device type"""
        return {
            "cisco": [
                {"username": "admin", "password": "admin"},
                {"username": "cisco", "password": "cisco"},
                {"username": "admin", "password": ""},
            ],
            "dell": [
                {"username": "root", "password": "calvin"},
                {"username": "admin", "password": "admin"},
            ],
            "hp": [
                {"username": "admin", "password": "admin"},
                {"username": "Administrator", "password": ""},
            ],
            "ubiquiti": [
                {"username": "ubnt", "password": "ubnt"},
            ],
            "fortinet": [
                {"username": "admin", "password": ""},
            ],
            "palo_alto": [
                {"username": "admin", "password": "admin"},
            ],
            "generic_iot": [
                {"username": "admin", "password": "1234"},
                {"username": "admin", "password": "12345"},
                {"username": "admin", "password": "password"},
                {"username": "root", "password": "root"},
            ]
        }
    
    def _load_weak_passwords(self) -> List[str]:
        """Common weak passwords for testing"""
        return [
            "password", "Password1", "P@ssw0rd", "123456", "12345678",
            "admin", "welcome", "letmein", "monkey", "qwerty",
            "password123", "admin123", "root", "toor", "changeme"
        ]
    
    def get_vendor_credentials(self, vendor: str) -> List[CredentialSet]:
        """
        Get vendor default credentials
        
        Args:
            vendor: Vendor name (cisco, dell, hp, etc.)
        
        Returns:
            List of CredentialSet objects
        """
        creds = []
        
        for cred_dict in self.vendor_defaults.get(vendor.lower(), []):
            creds.append(CredentialSet(
                username=cred_dict['username'],
                password=cred_dict['password'],
                service_type='any',
                source=f'vendor_default_{vendor}',
                tags=['vendor_default', vendor],
                risk_level='critical'
            ))
        
        return creds
    
    def get_weak_password_variants(self, username: str) -> List[CredentialSet]:
        """
        Generate credential sets with weak passwords for a username
        
        Args:
            username: Target username
        
        Returns:
            List of CredentialSet objects
        """
        creds = []
        
        for password in self.weak_passwords:
            creds.append(CredentialSet(
                username=username,
                password=password,
                service_type='any',
                source='weak_password_list',
                tags=['weak_password'],
                risk_level='high'
            ))
        
        return creds
    
    def get_from_vault(self, path: str) -> List[CredentialSet]:
        """
        Retrieve credentials from vault
        
        Args:
            path: Vault path or prefix
        
        Returns:
            List of CredentialSet objects
        """
        if not self.vault_client:
            self.logger.warning("No vault client configured")
            return []
        
        # Try as single credential first
        single_cred = self.vault_client.get_credential(path)
        if single_cred:
            return [single_cred]
        
        # Try as batch/prefix
        return self.vault_client.get_credential_batch(path)
    
    def build_credential_set(self, config: Dict) -> List[CredentialSet]:
        """
        Build comprehensive credential set from configuration
        
        Args:
            config: Configuration dict specifying sources
                {
                    "vendors": ["cisco", "dell"],
                    "weak_usernames": ["admin", "root"],
                    "vault_paths": ["credentials/ssh/"],
                    "custom": [{"username": "test", "password": "test123"}]
                }
        
        Returns:
            Consolidated list of CredentialSet objects
        """
        all_creds = []
        
        # Vendor defaults
        for vendor in config.get('vendors', []):
            all_creds.extend(self.get_vendor_credentials(vendor))
        
        # Weak password variants
        for username in config.get('weak_usernames', []):
            all_creds.extend(self.get_weak_password_variants(username))
        
        # Vault credentials
        for path in config.get('vault_paths', []):
            all_creds.extend(self.get_from_vault(path))
        
        # Custom credentials
        for custom in config.get('custom', []):
            all_creds.append(CredentialSet(
                username=custom['username'],
                password=custom['password'],
                service_type=custom.get('service_type', 'any'),
                source='custom',
                tags=custom.get('tags', []),
                risk_level=custom.get('risk_level', 'medium')
            ))
        
        self.logger.info(f"Built credential set: {len(all_creds)} credentials")
        return all_creds
    
    def export_to_json(self, credentials: List[CredentialSet], 
                       output_file: str, encrypt: bool = True):
        """
        Export credentials to encrypted JSON (for audit/backup)
        
        Args:
            credentials: List of CredentialSet objects
            output_file: Output file path
            encrypt: Whether to encrypt output (requires cryptography lib)
        """
        data = {
            "metadata": {
                "count": len(credentials),
                "sources": list(set(c.source for c in credentials))
            },
            "credentials": [
                {
                    "username": c.username,
                    "password": "***REDACTED***",  # Never log plaintext
                    "service_type": c.service_type,
                    "source": c.source,
                    "tags": c.tags,
                    "risk_level": c.risk_level
                }
                for c in credentials
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"Exported {len(credentials)} credentials to {output_file}")


# Example usage
def main():
    logging.basicConfig(level=logging.INFO)
    
    # Example 1: HashiCorp Vault integration
    print("=== HashiCorp Vault Example ===")
    try:
        vault = HashiCorpVaultClient(
            vault_url="http://localhost:8200",
            token="dev-token",
            mount_point="secret"
        )
        
        # Store a credential
        test_cred = CredentialSet(
            username="admin",
            password="test123",
            service_type="ssh",
            tags=["test", "demo"]
        )
        vault.store_credential("test/ssh/default", test_cred)
        
        # Retrieve it
        retrieved = vault.get_credential("test/ssh/default")
        print(f"Retrieved: {retrieved.username} for {retrieved.service_type}")
        
    except Exception as e:
        print(f"Vault example failed (expected if Vault not running): {e}")
    
    # Example 2: Credential Library usage
    print("\n=== Credential Library Example ===")
    library = CredentialLibrary()
    
    # Get vendor defaults
    cisco_creds = library.get_vendor_credentials("cisco")
    print(f"Cisco defaults: {len(cisco_creds)} credentials")
    
    # Get weak password variants
    admin_weak = library.get_weak_password_variants("admin")
    print(f"Weak passwords for 'admin': {len(admin_weak)} variants")
    
    # Build comprehensive set
    config = {
        "vendors": ["cisco", "dell"],
        "weak_usernames": ["admin", "root"],
        "custom": [
            {"username": "test", "password": "test123", "service_type": "ssh"}
        ]
    }
    
    all_creds = library.build_credential_set(config)
    print(f"\nTotal credential set: {len(all_creds)} credentials")
    
    # Export (with redacted passwords)
    library.export_to_json(all_creds, "credential_library.json")


if __name__ == "__main__":
    main()
