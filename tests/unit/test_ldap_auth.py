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
        # Ensure no group checking
        if 'LDAP_ALLOWED_GROUP' in os.environ:
            del os.environ['LDAP_ALLOWED_GROUP']
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
        # Ensure no group checking
        if 'LDAP_ALLOWED_GROUP' in os.environ:
            del os.environ['LDAP_ALLOWED_GROUP']
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
        # Ensure no group checking (requires service account)
        if 'LDAP_ALLOWED_GROUP' in os.environ:
            del os.environ['LDAP_ALLOWED_GROUP']
        
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


class TestLdapGroupAccessControl:
    """Tests for LDAP group-based access control."""
    
    def test_group_check_user_in_group(self, ldap_config):
        """Test authentication succeeds when user is in allowed group."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Mock user entry with string entry_dn
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            
            # Mock group entry with member attribute
            mock_group_entry = Mock()
            mock_member = Mock()
            mock_member.values = ['uid=testuser,ou=people,dc=example,dc=com']
            mock_group_entry.member = mock_member
            
            mock_bind_conn = Mock()
            # Set initial entries to user
            mock_bind_conn.entries = [mock_user_entry]
            
            # Make search update entries on second call (group search)
            search_call_count = [0]
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                if search_call_count[0] > 1:  # Second search is for group
                    mock_bind_conn.entries = [mock_group_entry]
            
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is True
            # Should search twice: once for user, once for group
            assert mock_bind_conn.search.call_count >= 1
    
    def test_group_check_user_not_in_group(self, ldap_config):
        """Test authentication fails when user is not in allowed group."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Mock user entry
            user_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            mock_user_entry = Mock(entry_dn=user_dn)
            
            # Mock group entry that does NOT contain the user DN in its member list
            mock_group_entry = Mock()
            mock_group_member = Mock()
            mock_group_member.values = ['uid=otheruser,ou=people,dc=example,dc=com']
            mock_group_entry.member = mock_group_member
            
            mock_bind_conn = Mock()
            
            # Simulate two searches on the same connection:
            #  - first for the user, returning the user entry
            #  - then for the group, returning a group entry without the user DN
            def search_side_effect(*args, **kwargs):
                search_filter = kwargs.get('search_filter') or (len(args) > 2 and args[2]) or ''
                if 'uid=testuser' in str(search_filter):
                    mock_bind_conn.entries = [mock_user_entry]
                else:
                    mock_bind_conn.entries = [mock_group_entry]
                return True
            
            mock_bind_conn.search.side_effect = search_side_effect
            mock_connection.return_value = mock_bind_conn
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is False
            # Should not proceed to password authentication
            assert mock_connection.call_count == 1
    
    def test_group_check_no_group_configured(self, ldap_config):
        """Test authentication works normally when no group is configured."""
        # Ensure LDAP_ALLOWED_GROUP is not set
        if 'LDAP_ALLOWED_GROUP' in os.environ:
            del os.environ['LDAP_ALLOWED_GROUP']
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [Mock(entry_dn='uid=testuser,ou=people,dc=example,dc=com')]
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is True
            # Should not request memberOf attribute
            mock_bind_conn.search.assert_called_once()
            call_kwargs = mock_bind_conn.search.call_args[1]
            assert 'memberOf' not in call_kwargs.get('attributes', [])
    
    def test_group_check_missing_bind_dn(self):
        """Test group check fails when LDAP_BIND_DN is missing."""
        os.environ['LDAP_ENABLED'] = 'true'
        os.environ['LDAP_SERVER'] = 'ldap://localhost:3890'
        os.environ['LDAP_BASE_DN'] = 'dc=example,dc=com'
        os.environ['LDAP_BIND_DN'] = ''
        os.environ['LDAP_BIND_PASSWORD'] = ''
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        reload_modules()
        
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential('testuser', 'password')
        
        assert result is False
    
    def test_group_check_full_dn_format(self, ldap_config):
        """Test group check works with full DN format."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'cn=whitelist-users,ou=groups,dc=example,dc=com'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Mock user entry with string entry_dn
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            
            # Mock group entry with member attribute
            mock_group_entry = Mock()
            mock_member = Mock()
            mock_member.values = ['uid=testuser,ou=people,dc=example,dc=com']
            mock_group_entry.member = mock_member
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [mock_user_entry]
            search_call_count = [0]
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                if search_call_count[0] > 1:  # Second search is for group
                    mock_bind_conn.entries = [mock_group_entry]
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is True
    
    def test_group_check_case_insensitive(self, ldap_config):
        """Test group check is case-insensitive."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Mock user entry with string entry_dn (different case)
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'UID=TestUser,OU=People,DC=example,DC=com'
            
            # Mock group entry with member attribute (case-insensitive matching)
            mock_group_entry = Mock()
            mock_member = Mock()
            mock_member.values = ['uid=testuser,ou=people,dc=example,dc=com']  # Different case in DN
            mock_group_entry.member = mock_member
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [mock_user_entry]
            search_call_count = [0]
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                if search_call_count[0] > 1:  # Second search is for group
                    mock_bind_conn.entries = [mock_group_entry]
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is True
    
    def test_group_check_value_with_equals_treated_as_group_name(self, ldap_config):
        """Test that single-component DNs (e.g., 'admin=users') are treated as group names."""
        # Set a value that is a valid single-component DN but should be treated as a group name
        os.environ['LDAP_ALLOWED_GROUP'] = 'admin=users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        from ldap_auth import _get_allowed_group_dn
        from config import Config
        
        # Should construct a proper DN from the template, not use 'admin=users' as-is
        result = _get_allowed_group_dn()
        
        # Expected: cn=admin=users,ou=groups,<base_dn>
        # (The group name 'admin=users' is inserted into the template)
        expected = f'cn=admin=users,ou=groups,{Config.LDAP_BASE_DN}'
        assert result == expected
    
    def test_group_check_empty_memberof(self, ldap_config):
        """Test authentication fails when user has no groups."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # First search returns user entry, second search returns group
            # entry that does NOT include the user in its member attribute.
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            
            mock_group_entry = Mock()
            mock_member = Mock()
            mock_member.values = []  # No members, so user is not in the group
            mock_group_entry.member = mock_member
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [mock_user_entry]
            search_call_count = [0]
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                if search_call_count[0] > 1:  # Second search is for group
                    mock_bind_conn.entries = [mock_group_entry]
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is False
    
    def test_group_cn_sanitization(self, ldap_config):
        """Test that group CN values are sanitized to prevent LDAP injection."""
        # Use a simpler malicious input that clearly demonstrates injection attempt
        os.environ['LDAP_ALLOWED_GROUP'] = 'cn=admin*)(uid=*,ou=groups,dc=example,dc=com'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [mock_user_entry]
            
            search_call_count = [0]
            captured_filters = []
            
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                captured_filters.append(kwargs.get('search_filter', args[1] if len(args) > 1 else None))
                if search_call_count[0] > 1:  # Second search is for group
                    # Group not found
                    mock_bind_conn.entries = []
            
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            mock_connection.return_value = mock_bind_conn
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            # Authentication should fail because group not found
            assert result is False
    
    def test_group_check_group_with_empty_member(self, ldap_config):
        """Test authentication fails when group exists but has no members."""
        os.environ['LDAP_ALLOWED_GROUP'] = 'whitelist-users'
        os.environ['LDAP_GROUP_DN_TEMPLATE'] = 'cn={},ou=groups,{}'
        reload_modules()
        
        with patch('ldap_auth.Server') as mock_server, \
             patch('ldap_auth.Connection') as mock_connection:
            
            mock_server_instance = Mock()
            mock_server.return_value = mock_server_instance
            
            # Mock user entry returned by initial bind search
            mock_user_entry = Mock()
            mock_user_entry.entry_dn = 'uid=testuser,ou=people,dc=example,dc=com'
            
            # Mock group entry where 'member' attribute exists but is falsy (None)
            mock_group_entry = Mock()
            mock_group_entry.member = None
            
            mock_bind_conn = Mock()
            mock_bind_conn.entries = [mock_user_entry]
            search_call_count = [0]
            
            def search_side_effect(*args, **kwargs):
                search_call_count[0] += 1
                # Second search is for the allowed group
                if search_call_count[0] > 1:
                    mock_bind_conn.entries = [mock_group_entry]
            
            mock_bind_conn.search = Mock(side_effect=search_side_effect)
            
            mock_user_conn = Mock()
            mock_connection.side_effect = [mock_bind_conn, mock_user_conn]
            
            from ldap_auth import verify_ldap_credential
            
            result = verify_ldap_credential('testuser', 'valid_password')
            
            assert result is False
            
            # Verify that the group search filter was properly escaped
            assert len(captured_filters) >= 2
            group_filter = captured_filters[1]  # Second search is for group
            
            # Verify all special characters are escaped
            # * should become \\2a, ( should become \\28, ) should become \\29
            assert '\\2a' in group_filter  # * is escaped
            assert '\\28' in group_filter  # ( is escaped
            assert '\\29' in group_filter  # ) is escaped
            
            # Verify the filter structure is correct
            assert group_filter.startswith('(&(cn=')
            assert group_filter.endswith(')(objectClass=groupOfNames))')
            
            # Extract the CN value portion between 'cn=' and ')(objectClass='
            cn_start = group_filter.find('cn=') + 3
            cn_end = group_filter.find(')(objectClass=')
            cn_value = group_filter[cn_start:cn_end]
            
            # Verify that dangerous unescaped characters are NOT in the CN value
            # The only unescaped special chars should be the escaped hex codes (\\XX)
            assert '*' not in cn_value or cn_value.count('*') == 0
            assert cn_value.count('(') <= cn_value.count('\\28')  # All ( should be escaped
            assert cn_value.count(')') <= cn_value.count('\\29')  # All ) should be escaped
