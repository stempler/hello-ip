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

