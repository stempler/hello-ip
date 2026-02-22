"""Shared pytest fixtures for authentication tests."""
import os
import sys
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def reload_modules():
    """Reload config and ldap_auth modules to pick up env var changes.
    
    This function removes cached modules from sys.modules to force reimport
    with updated environment variables. Should be called after modifying
    environment variables that affect module-level configuration.
    """
    modules_to_reload = ['config', 'ldap_auth', 'database']
    for mod in modules_to_reload:
        if mod in sys.modules:
            del sys.modules[mod]


@pytest.fixture
def reload_modules_fixture():
    """Fixture that provides reload_modules function and auto-reloads after test."""
    yield reload_modules
    # Optionally reload after test to ensure clean state
    reload_modules()


@pytest.fixture
def temp_db():
    """Create a temporary database file for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name
    
    # Set environment variable before importing modules
    os.environ['DATABASE_PATH'] = db_path
    
    yield db_path
    
    # Cleanup
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def sample_credentials():
    """Sample credentials for testing.
    
    Returns dict with credential_id -> (plain_password, password_hash)
    """
    from werkzeug.security import generate_password_hash
    
    credentials = {
        'admin': ('secret123', generate_password_hash('secret123')),
        'user1': ('password456', generate_password_hash('password456')),
    }
    return credentials


@pytest.fixture
def set_local_credentials(sample_credentials):
    """Set up local credentials in environment."""
    import json
    
    # Create credentials dict with only hashes
    creds_env = {
        cred_id: hash_val
        for cred_id, (_, hash_val) in sample_credentials.items()
    }
    
    original = os.environ.get('CREDENTIALS')
    os.environ['CREDENTIALS'] = json.dumps(creds_env)
    
    yield sample_credentials
    
    # Restore original
    if original is not None:
        os.environ['CREDENTIALS'] = original
    elif 'CREDENTIALS' in os.environ:
        del os.environ['CREDENTIALS']


@pytest.fixture
def disable_ldap():
    """Disable LDAP authentication for testing."""
    original = os.environ.get('LDAP_ENABLED')
    os.environ['LDAP_ENABLED'] = 'false'
    
    yield
    
    if original is not None:
        os.environ['LDAP_ENABLED'] = original
    elif 'LDAP_ENABLED' in os.environ:
        del os.environ['LDAP_ENABLED']


@pytest.fixture
def enable_ldap():
    """Enable LDAP authentication for testing."""
    original = os.environ.get('LDAP_ENABLED')
    os.environ['LDAP_ENABLED'] = 'true'
    
    yield
    
    if original is not None:
        os.environ['LDAP_ENABLED'] = original
    elif 'LDAP_ENABLED' in os.environ:
        del os.environ['LDAP_ENABLED']


@pytest.fixture
def ldap_config():
    """Set up LDAP configuration for testing."""
    original_values = {}
    config_vars = {
        'LDAP_ENABLED': 'true',
        'LDAP_SERVER': 'ldap://localhost:3890',
        'LDAP_BASE_DN': 'dc=example,dc=com',
        'LDAP_BIND_DN': 'uid=admin,ou=people,dc=example,dc=com',
        'LDAP_BIND_PASSWORD': 'admin_password',
        'LDAP_USER_FILTER': '(&(objectClass=person)(uid={}))',
        'LDAP_USER_DN_TEMPLATE': 'uid={},ou=people,{}',
        'LDAP_USE_TLS': 'false',
        'LDAP_FALLBACK_LOCAL': 'true',
    }
    
    # Save original values and set test values
    for key, value in config_vars.items():
        original_values[key] = os.environ.get(key)
        os.environ[key] = value
    
    # Ensure LDAP_ALLOWED_GROUP is not set unless explicitly needed
    if 'LDAP_ALLOWED_GROUP' in os.environ:
        original_values['LDAP_ALLOWED_GROUP'] = os.environ['LDAP_ALLOWED_GROUP']
        del os.environ['LDAP_ALLOWED_GROUP']
    
    reload_modules()
    
    yield config_vars
    
    # Restore original values
    for key, original in original_values.items():
        if original is not None:
            os.environ[key] = original
        elif key in os.environ:
            del os.environ[key]
    reload_modules()


@pytest.fixture
def ldap_no_fallback(ldap_config):
    """LDAP config without fallback to local credentials."""
    original = os.environ.get('LDAP_FALLBACK_LOCAL')
    os.environ['LDAP_FALLBACK_LOCAL'] = 'false'
    reload_modules()
    
    yield ldap_config
    
    if original is not None:
        os.environ['LDAP_FALLBACK_LOCAL'] = original
    elif 'LDAP_FALLBACK_LOCAL' in os.environ:
        del os.environ['LDAP_FALLBACK_LOCAL']
    reload_modules()


@pytest.fixture
def ldap_no_bind_credentials():
    """LDAP config without service account (direct user bind)."""
    original_values = {}
    config_vars = {
        'LDAP_ENABLED': 'true',
        'LDAP_SERVER': 'ldap://localhost:3890',
        'LDAP_BASE_DN': 'dc=example,dc=com',
        'LDAP_BIND_DN': '',
        'LDAP_BIND_PASSWORD': '',
        'LDAP_USER_DN_TEMPLATE': 'uid={},ou=people,{}',
        'LDAP_USER_FILTER': '(&(objectClass=person)(uid={}))',
        'LDAP_USE_TLS': 'false',
        'LDAP_FALLBACK_LOCAL': 'true',
    }
    
    # Save original values and set test values
    for key, value in config_vars.items():
        original_values[key] = os.environ.get(key)
        os.environ[key] = value
    
    # Ensure no group checking (requires service account)
    if 'LDAP_ALLOWED_GROUP' in os.environ:
        original_values['LDAP_ALLOWED_GROUP'] = os.environ['LDAP_ALLOWED_GROUP']
        del os.environ['LDAP_ALLOWED_GROUP']
    
    reload_modules()
    
    yield config_vars
    
    # Restore original values
    for key, original in original_values.items():
        if original is not None:
            os.environ[key] = original
        elif key in os.environ:
            del os.environ[key]
    reload_modules()


class LDAPGroupAccessContext:
    """Context manager for LDAP group access configuration."""
    
    def __init__(self, group_name_or_dn, group_dn_template='cn={},ou=groups,{}'):
        self.group_name_or_dn = group_name_or_dn
        self.group_dn_template = group_dn_template
        self.original_values = {}
    
    def __enter__(self):
        # Start with base LDAP config
        config_vars = {
            'LDAP_ENABLED': 'true',
            'LDAP_SERVER': 'ldap://localhost:3890',
            'LDAP_BASE_DN': 'dc=example,dc=com',
            'LDAP_BIND_DN': 'uid=admin,ou=people,dc=example,dc=com',
            'LDAP_BIND_PASSWORD': 'admin_password',
            'LDAP_USER_FILTER': '(&(objectClass=person)(uid={}))',
            'LDAP_USER_DN_TEMPLATE': 'uid={},ou=people,{}',
            'LDAP_USE_TLS': 'false',
            'LDAP_FALLBACK_LOCAL': 'true',
            'LDAP_ALLOWED_GROUP': self.group_name_or_dn,
            'LDAP_GROUP_DN_TEMPLATE': self.group_dn_template,
        }
        
        # Save original values and set test values
        for key, value in config_vars.items():
            self.original_values[key] = os.environ.get(key)
            os.environ[key] = value
        
        reload_modules()
        return config_vars
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore original values
        for key, original in self.original_values.items():
            if original is not None:
                os.environ[key] = original
            elif key in os.environ:
                del os.environ[key]
        reload_modules()
        return False


@pytest.fixture
def ldap_with_group_access():
    """Fixture that returns a context manager for LDAP group access configuration."""
    return LDAPGroupAccessContext


@pytest.fixture
def flask_test_client(temp_db, set_local_credentials, disable_ldap):
    """Create Flask test client with initialized database."""
    # Import after setting environment
    import database
    from app import main_app
    
    # Initialize database
    database.init_db()
    
    # Create test client
    main_app.config['TESTING'] = True
    with main_app.test_client() as client:
        yield client


@pytest.fixture
def initialized_db(temp_db):
    """Initialize database for testing."""
    import database
    database.init_db()
    yield

