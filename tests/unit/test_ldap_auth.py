"""Unit tests for LDAP authentication with mocked ldap3."""
import os
import sys
import importlib
import pytest
from unittest.mock import Mock, patch, MagicMock


def reload_modules():
    """Reload config and ldap_auth modules to pick up env var changes."""
    # Remove cached modules to force reimport with new env vars
    modules_to_reload = ['config', 'ldap_auth', 'database']
    for mod in modules_to_reload:
        if mod in sys.modules:
            del sys.modules[mod]


class TestLdapDisabled:
    """Tests when LDAP is disabled."""
    
    def test_ldap_disabled_uses_local(self, temp_db, set_local_credentials, disable_ldap):
        """When LDAP disabled, should use local credentials only."""
        reload_modules()
        from database import verify_credential
        
        # Should succeed with local credentials
        assert verify_credential('admin', 'secret123') is True
        
        # Should fail with wrong password
        assert verify_credential('admin', 'wrong') is False
    
    def test_ldap_disabled_verify_returns_false(self, disable_ldap):
        """verify_ldap_credential should return False when disabled."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential('admin', 'secret123')
        assert result is False


class TestLdapAuthMocked:
    """Tests for LDAP authentication with mocked ldap3 library."""
    
    def test_ldap_valid_credentials(self, ldap_config):
        """Test LDAP authentication with valid credentials."""
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            # Set up mock server
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Set up mock connection for bind (service account)
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [Mock(entry_dn='uid=testuser,ou=people,dc=example,dc=com')]
            
            # Set up mock connection for user auth
            mock_user_conn = Mock()
            
            # Connection returns different mocks based on call order
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is True
            assert mock_connection.call_count == 2
    
    def test_ldap_invalid_password(self, ldap_config):
        """Test LDAP authentication with invalid password."""
        reload_modules()
        from ldap3.core.exceptions import LDAPBindError
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # First connection for bind succeeds
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [Mock(entry_dn='uid=testuser,ou=people,dc=example,dc=com')]
            
            # Second connection (user bind) raises error
            mock_connection.side_effect = [mock_bind_conn, LDAPBindError('Invalid credentials')]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'wrong_password')
            
            assert result is False
    
    def test_ldap_user_not_found(self, ldap_config):
        """Test LDAP authentication when user is not found."""
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Bind connection returns no entries (user not found)
            mock_bind_conn = Mock()
            mock_bind_conn.entries = []
            mock_connection.return_value = mock_bind_conn
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('unknown_user', 'password')
            
            assert result is False
    
    def test_ldap_server_unreachable(self, ldap_config):
        """Test LDAP authentication when server is unreachable."""
        reload_modules()
        from ldap3.core.exceptions import LDAPException
        
        with patch('ldap_auth.Server') as mock_server:
            mock_server.side_effect = LDAPException('Server unreachable')
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'password')
            
            assert result is False
    
    def test_ldap_empty_password_rejected(self, ldap_config):
        """Empty password should be rejected without contacting server."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential('testuser', '')
        
        assert result is False


class TestLdapFallback:
    """Tests for LDAP fallback to local credentials."""
    
    def test_ldap_fails_fallback_to_local(self, temp_db, set_local_credentials, ldap_config):
        """When LDAP fails and fallback enabled, should try local credentials."""
        reload_modules()
        from ldap3.core.exceptions import LDAPException
        
        with patch('ldap_auth.Server') as mock_server:
            # LDAP connection fails
            mock_server.side_effect = LDAPException('Connection failed')
            
            from database import verify_credential
            
            # Should fall back to local credentials and succeed
            result = verify_credential('admin', 'secret123')
            assert result is True
    
    def test_ldap_fails_no_fallback(self, temp_db, set_local_credentials, ldap_no_fallback):
        """When LDAP fails and fallback disabled, should fail."""
        reload_modules()
        from ldap3.core.exceptions import LDAPException
        
        with patch('ldap_auth.Server') as mock_server:
            # LDAP connection fails
            mock_server.side_effect = LDAPException('Connection failed')
            
            from database import verify_credential
            
            # Should not fall back to local credentials
            result = verify_credential('admin', 'secret123')
            assert result is False
    
    def test_ldap_succeeds_no_local_check(self, temp_db, set_local_credentials, ldap_config):
        """When LDAP succeeds, should not check local credentials."""
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [Mock(entry_dn='uid=ldap_only_user,ou=people,dc=example,dc=com')]
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from database import verify_credential
            
            # User exists only in LDAP, not in local credentials
            result = verify_credential('ldap_only_user', 'ldap_password')
            
            # Should succeed via LDAP
            assert result is True


class TestLdapWithoutBindCredentials:
    """Tests for LDAP auth without service account (direct user bind)."""
    
    def test_direct_user_bind(self):
        """Test LDAP with direct user bind (no service account)."""
        # Set up environment for LDAP without bind credentials
        os.environ['LDAP_ENABLED'] = 'true'
        os.environ['LDAP_SERVER'] = 'ldap://localhost:3890'
        os.environ['LDAP_BASE_DN'] = 'dc=example,dc=com'
        os.environ['LDAP_BIND_DN'] = ''
        os.environ['LDAP_BIND_PASSWORD'] = ''
        os.environ['LDAP_USER_DN_TEMPLATE'] = 'uid={},ou=people,{}'
        os.environ['LDAP_USE_TLS'] = 'false'
        
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            mock_user_conn = Mock()
            mock_connection.return_value = mock_user_conn
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'password')
            
            # Should only make one connection (direct user bind)
            assert result is True
            assert mock_connection.call_count == 1
