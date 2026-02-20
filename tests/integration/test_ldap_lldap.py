"""Integration tests for LDAP authentication using LLDAP container."""
import os
import sys
import time
import pytest

# Skip all tests in this module if Docker is not available
pytestmark = pytest.mark.integration


def reload_modules():
    """Reload config and ldap_auth modules to pick up env var changes."""
    modules_to_reload = ['config', 'ldap_auth', 'database']
    for mod in modules_to_reload:
        if mod in sys.modules:
            del sys.modules[mod]


def is_docker_available():
    """Check if Docker is available."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


# Skip module if Docker not available
if not is_docker_available():
    pytest.skip("Docker not available", allow_module_level=True)


class LLDAPContainer:
    """Context manager for LLDAP container."""
    
    def __init__(self):
        self.container = None
        self.ldap_port = None
        self.base_dn = "dc=example,dc=com"
        self.admin_password = "admin_password"
        
    def __enter__(self):
        import docker
        
        client = docker.from_env()
        
        # Start LLDAP container
        self.container = client.containers.run(
            "lldap/lldap:stable",
            detach=True,
            environment={
                "LLDAP_LDAP_BASE_DN": self.base_dn,
                "LLDAP_LDAP_USER_PASS": self.admin_password,
                "LLDAP_JWT_SECRET": "test_jwt_secret_for_testing_only",
            },
            ports={
                "3890/tcp": None,  # Let Docker assign a random port
                "17170/tcp": None,
            },
            remove=True,
        )
        
        # Wait for container to be ready
        self._wait_for_ready()
        
        # Get assigned port
        self.container.reload()
        self.ldap_port = self.container.ports["3890/tcp"][0]["HostPort"]
        self.web_port = self.container.ports["17170/tcp"][0]["HostPort"]
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.container:
            self.container.stop()
    
    def _wait_for_ready(self, timeout=30):
        """Wait for LLDAP to be ready."""
        import socket
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                self.container.reload()
                if self.container.status != "running":
                    time.sleep(0.5)
                    continue
                
                # Try to connect to LDAP port
                port_mapping = self.container.ports.get("3890/tcp")
                if port_mapping:
                    host_port = port_mapping[0]["HostPort"]
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(("localhost", int(host_port)))
                    sock.close()
                    if result == 0:
                        # Give LLDAP a moment to fully initialize
                        time.sleep(2)
                        return
            except Exception:
                pass
            time.sleep(0.5)
        
        raise TimeoutError("LLDAP container did not become ready in time")
    
    def get_ldap_url(self):
        """Get LDAP URL for connecting to the container."""
        return f"ldap://localhost:{self.ldap_port}"
    
    def create_test_user(self, username, password):
        """Create a test user in LLDAP via the GraphQL API and set password.
        
        LLDAP uses the OPAQUE protocol for password setting, which requires
        using the lldap_set_password binary included in the Docker image.
        
        Returns True if user was created successfully, False otherwise.
        """
        import requests
        
        # Login to get JWT token
        login_url = f"http://localhost:{self.web_port}/auth/simple/login"
        login_data = {
            "username": "admin",
            "password": self.admin_password,
        }
        
        try:
            response = requests.post(login_url, json=login_data, timeout=10)
            response.raise_for_status()
            token = response.json().get("token")
        except Exception as e:
            print(f"Could not authenticate with LLDAP admin: {e}")
            return False
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        # Create user via GraphQL
        graphql_url = f"http://localhost:{self.web_port}/api/graphql"
        
        create_user_query = """
        mutation CreateUser($user: CreateUserInput!) {
            createUser(user: $user) {
                id
                displayName
            }
        }
        """
        
        variables = {
            "user": {
                "id": username,
                "email": f"{username}@example.com",
                "displayName": username.title(),
            }
        }
        
        try:
            response = requests.post(
                graphql_url,
                json={"query": create_user_query, "variables": variables},
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()
            result = response.json()
            if "errors" in result:
                print(f"GraphQL error creating user: {result['errors']}")
                return False
        except Exception as e:
            print(f"Could not create test user: {e}")
            return False
        
        # Set password using lldap_set_password via docker exec
        # LLDAP uses OPAQUE protocol which requires the binary tool
        try:
            # The lldap_set_password binary is at /app/lldap_set_password in the container
            exit_code, output = self.container.exec_run(
                cmd=[
                    "/app/lldap_set_password",
                    "--base-url", "http://localhost:17170/",
                    "--admin-username", "admin",
                    "--admin-password", self.admin_password,
                    "--username", username,
                    "--password", password,
                ],
                environment={"RUST_LOG": "warn"},
            )
            
            if exit_code != 0:
                print(f"lldap_set_password failed (exit {exit_code}): {output.decode()}")
                return False
            
            return True
        except Exception as e:
            print(f"Could not set password via lldap_set_password: {e}")
            return False


@pytest.fixture(scope="module")
def lldap_container():
    """Start LLDAP container for integration tests."""
    try:
        with LLDAPContainer() as container:
            yield container
    except Exception as e:
        pytest.skip(f"Could not start LLDAP container: {e}")


@pytest.fixture
def ldap_env(lldap_container):
    """Configure environment for LLDAP testing."""
    original_values = {}
    config_vars = {
        "LDAP_ENABLED": "true",
        "LDAP_SERVER": lldap_container.get_ldap_url(),
        "LDAP_BASE_DN": lldap_container.base_dn,
        "LDAP_BIND_DN": f"uid=admin,ou=people,{lldap_container.base_dn}",
        "LDAP_BIND_PASSWORD": lldap_container.admin_password,
        "LDAP_USER_FILTER": "(&(objectClass=person)(uid={}))",
        "LDAP_USER_DN_TEMPLATE": "uid={},ou=people,{}",
        "LDAP_USE_TLS": "false",
        "LDAP_FALLBACK_LOCAL": "false",
    }
    
    for key, value in config_vars.items():
        original_values[key] = os.environ.get(key)
        os.environ[key] = value
    
    yield config_vars
    
    for key, original in original_values.items():
        if original is not None:
            os.environ[key] = original
        elif key in os.environ:
            del os.environ[key]


class TestLLDAPIntegration:
    """Integration tests using real LLDAP container."""
    
    def test_admin_authentication(self, lldap_container, ldap_env, temp_db):
        """Test authentication with LLDAP admin user."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        # Admin user should be able to authenticate
        result = verify_ldap_credential("admin", lldap_container.admin_password)
        
        assert result is True
    
    def test_invalid_password(self, lldap_container, ldap_env, temp_db):
        """Test authentication with invalid password."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential("admin", "wrong_password")
        
        assert result is False
    
    def test_unknown_user(self, lldap_container, ldap_env, temp_db):
        """Test authentication with unknown user."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential("nonexistent_user", "any_password")
        
        assert result is False
    
    def test_empty_password(self, lldap_container, ldap_env, temp_db):
        """Test authentication with empty password."""
        reload_modules()
        from ldap_auth import verify_ldap_credential
        
        result = verify_ldap_credential("admin", "")
        
        assert result is False
    
    def test_full_auth_flow(self, lldap_container, ldap_env, temp_db):
        """Test full authentication through verify_credential."""
        reload_modules()
        import database
        
        database.init_db()
        
        # Should succeed with valid LDAP credentials
        result = database.verify_credential("admin", lldap_container.admin_password)
        assert result is True
        
        # Should fail with invalid password
        result = database.verify_credential("admin", "wrong")
        assert result is False
    
    def test_user_search_finds_admin(self, lldap_container, ldap_env, temp_db):
        """Test that LDAP user search correctly finds the admin user."""
        reload_modules()
        from ldap3 import Server, Connection, SUBTREE
        
        server = Server(lldap_container.get_ldap_url())
        admin_dn = f"uid=admin,ou=people,{lldap_container.base_dn}"
        
        conn = Connection(
            server,
            user=admin_dn,
            password=lldap_container.admin_password,
            auto_bind=True
        )
        
        # Search for admin user
        search_filter = "(&(objectClass=person)(uid=admin))"
        conn.search(
            search_base=lldap_container.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[]
        )
        
        assert len(conn.entries) == 1
        assert "admin" in str(conn.entries[0].entry_dn).lower()
        
        conn.unbind()
    
    def test_user_search_not_found(self, lldap_container, ldap_env, temp_db):
        """Test that LDAP user search returns empty for non-existent user."""
        reload_modules()
        from ldap3 import Server, Connection, SUBTREE
        
        server = Server(lldap_container.get_ldap_url())
        admin_dn = f"uid=admin,ou=people,{lldap_container.base_dn}"
        
        conn = Connection(
            server,
            user=admin_dn,
            password=lldap_container.admin_password,
            auto_bind=True
        )
        
        # Search for non-existent user
        search_filter = "(&(objectClass=person)(uid=nonexistent_user_xyz))"
        conn.search(
            search_base=lldap_container.base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[]
        )
        
        assert len(conn.entries) == 0
        
        conn.unbind()
    
    def test_non_admin_user_authentication(self, lldap_container, ldap_env, temp_db):
        """Test authentication with a created non-admin user."""
        reload_modules()
        
        # Create a test user with password
        test_username = "testuser"
        test_password = "testpassword123"
        
        created = lldap_container.create_test_user(test_username, test_password)
        if not created:
            pytest.skip("Could not create test user in LLDAP")
        
        from ldap_auth import verify_ldap_credential
        
        # Should succeed with correct password
        result = verify_ldap_credential(test_username, test_password)
        assert result is True
        
        # Should fail with wrong password
        result = verify_ldap_credential(test_username, "wrong_password")
        assert result is False
    
    def test_non_admin_full_auth_flow(self, lldap_container, ldap_env, temp_db):
        """Test full auth flow with a non-admin user including whitelist."""
        reload_modules()
        import database
        
        database.init_db()
        
        # Create a test user with password
        test_username = "whitelistuser"
        test_password = "whitelistpass123"
        
        created = lldap_container.create_test_user(test_username, test_password)
        if not created:
            pytest.skip("Could not create test user in LLDAP")
        
        # Authenticate through the full credential flow
        result = database.verify_credential(test_username, test_password)
        assert result is True
        
        # Wrong password should fail
        result = database.verify_credential(test_username, "badpassword")
        assert result is False

