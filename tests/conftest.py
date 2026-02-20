"""Shared pytest fixtures for authentication tests."""
import os
import sys
import tempfile
import pytest

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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
    
    yield config_vars
    
    # Restore original values
    for key, original in original_values.items():
        if original is not None:
            os.environ[key] = original
        elif key in os.environ:
            del os.environ[key]


@pytest.fixture
def ldap_no_fallback(ldap_config):
    """LDAP config without fallback to local credentials."""
    original = os.environ.get('LDAP_FALLBACK_LOCAL')
    os.environ['LDAP_FALLBACK_LOCAL'] = 'false'
    
    yield ldap_config
    
    if original is not None:
        os.environ['LDAP_FALLBACK_LOCAL'] = original


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

