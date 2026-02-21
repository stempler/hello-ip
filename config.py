"""Configuration management from environment variables."""
import os
import json
from typing import Dict


class Config:
    """Application configuration loaded from environment variables."""
    
    BASE_PATH: str = os.getenv('BASE_PATH', '/').rstrip('/') or '/'
    MAIN_PORT: int = int(os.getenv('MAIN_PORT', '8080'))
    INTERNAL_PORT: int = int(os.getenv('INTERNAL_PORT', '8081'))
    ENTRY_VALIDITY_HOURS: int = int(os.getenv('ENTRY_VALIDITY_HOURS', '24'))
    MAX_ENTRIES: int = int(os.getenv('MAX_ENTRIES', '1000'))
    DATABASE_PATH: str = os.getenv('DATABASE_PATH', '/data/whitelist.db')
    
    # LDAP authentication (defaults target LLDAP)
    LDAP_ENABLED: bool = os.getenv('LDAP_ENABLED', 'false').lower() == 'true'
    LDAP_SERVER: str = os.getenv('LDAP_SERVER', 'ldap://localhost:3890')
    LDAP_BASE_DN: str = os.getenv('LDAP_BASE_DN', 'dc=example,dc=com')
    LDAP_BIND_DN: str = os.getenv('LDAP_BIND_DN', 'uid=admin,ou=people,dc=example,dc=com')
    LDAP_BIND_PASSWORD: str = os.getenv('LDAP_BIND_PASSWORD', '')
    LDAP_USER_DN_TEMPLATE: str = os.getenv('LDAP_USER_DN_TEMPLATE', 'uid={},ou=people,{}')
    LDAP_USER_FILTER: str = os.getenv('LDAP_USER_FILTER', '(&(objectClass=person)(uid={}))')
    LDAP_USE_TLS: bool = os.getenv('LDAP_USE_TLS', 'false').lower() == 'true'
    LDAP_FALLBACK_LOCAL: bool = os.getenv('LDAP_FALLBACK_LOCAL', 'true').lower() == 'true'
    LDAP_ALLOWED_GROUP: str = os.getenv('LDAP_ALLOWED_GROUP', '')
    LDAP_GROUP_DN_TEMPLATE: str = os.getenv('LDAP_GROUP_DN_TEMPLATE', 'cn={},ou=groups,{}')
    
    # BunkerWeb API integration
    BUNKERWEB_ENABLED: bool = os.getenv('BUNKERWEB_ENABLED', 'false').lower() == 'true'
    BUNKERWEB_API_URL: str = os.getenv('BUNKERWEB_API_URL', '').rstrip('/')
    BUNKERWEB_USERNAME: str = os.getenv('BUNKERWEB_USERNAME', '')
    BUNKERWEB_PASSWORD: str = os.getenv('BUNKERWEB_PASSWORD', '')
    BUNKERWEB_JOB_PLUGIN: str = os.getenv('BUNKERWEB_JOB_PLUGIN', 'greylist')
    BUNKERWEB_JOB_NAME: str = os.getenv('BUNKERWEB_JOB_NAME', 'greylist-download')
    BUNKERWEB_UNBAN_ENABLED: bool = os.getenv('BUNKERWEB_UNBAN_ENABLED', 'false').lower() == 'true'
    
    @staticmethod
    def get_credentials() -> Dict[str, str]:
        """Parse credentials from environment variable.
        
        Returns a dictionary mapping credential IDs to password hashes.
        The CREDENTIALS environment variable should contain a JSON object
        with credential IDs as keys and Werkzeug password hashes as values.
        Use the hash_password.py script to generate hashes.
        """
        credentials_str = os.getenv('CREDENTIALS', '{}')
        try:
            return json.loads(credentials_str)
        except json.JSONDecodeError:
            return {}

