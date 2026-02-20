"""Unit tests for local credential authentication."""
import os
import json
import pytest


class TestLocalCredentialVerification:
    """Tests for verify_local_credential function."""
    
    def test_valid_credentials(self, temp_db, set_local_credentials, disable_ldap):
        """Test authentication with valid credentials."""
        # Import after fixtures set up environment
        from database import verify_credential
        
        credentials = set_local_credentials
        for cred_id, (plain_password, _) in credentials.items():
            assert verify_credential(cred_id, plain_password) is True
    
    def test_invalid_password(self, temp_db, set_local_credentials, disable_ldap):
        """Test authentication with invalid password."""
        from database import verify_credential
        
        assert verify_credential('admin', 'wrong_password') is False
    
    def test_unknown_credential_id(self, temp_db, set_local_credentials, disable_ldap):
        """Test authentication with unknown credential ID."""
        from database import verify_credential
        
        assert verify_credential('unknown_user', 'any_password') is False
    
    def test_empty_password(self, temp_db, set_local_credentials, disable_ldap):
        """Test authentication with empty password."""
        from database import verify_credential
        
        assert verify_credential('admin', '') is False
    
    def test_empty_credential_id(self, temp_db, set_local_credentials, disable_ldap):
        """Test authentication with empty credential ID."""
        from database import verify_credential
        
        assert verify_credential('', 'secret123') is False
    
    def test_both_empty(self, temp_db, disable_ldap):
        """Test authentication with both empty."""
        os.environ['CREDENTIALS'] = '{}'
        
        from database import verify_credential
        
        assert verify_credential('', '') is False


class TestCredentialsEnvParsing:
    """Tests for CREDENTIALS environment variable parsing."""
    
    def test_empty_credentials_env(self, temp_db, disable_ldap):
        """Test with empty CREDENTIALS environment variable."""
        os.environ['CREDENTIALS'] = '{}'
        
        from database import verify_credential
        
        assert verify_credential('admin', 'secret123') is False
    
    def test_malformed_json_credentials(self, temp_db, disable_ldap):
        """Test with malformed JSON in CREDENTIALS."""
        os.environ['CREDENTIALS'] = 'not valid json'
        
        # Need to reload config to pick up new env var
        from config import Config
        
        # Should return empty dict and not crash
        credentials = Config.get_credentials()
        assert credentials == {}
    
    def test_missing_credentials_env(self, temp_db, disable_ldap):
        """Test with missing CREDENTIALS environment variable."""
        if 'CREDENTIALS' in os.environ:
            del os.environ['CREDENTIALS']
        
        from config import Config
        
        credentials = Config.get_credentials()
        assert credentials == {}


class TestVerifyLocalCredentialFunction:
    """Tests for verify_local_credential helper function."""
    
    def test_verify_local_credential_directly(self, temp_db, set_local_credentials):
        """Test verify_local_credential function directly."""
        from database import verify_local_credential
        
        credentials = set_local_credentials
        
        # Valid credentials
        assert verify_local_credential('admin', 'secret123') is True
        assert verify_local_credential('user1', 'password456') is True
        
        # Invalid credentials
        assert verify_local_credential('admin', 'wrong') is False
        assert verify_local_credential('unknown', 'secret123') is False

