"""LDAP authentication module for alternative credential verification."""
import logging
from typing import Optional
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException, LDAPBindError
from config import Config

logger = logging.getLogger(__name__)


def verify_ldap_credential(username: str, password: str) -> bool:
    """Verify credentials against LDAP server.
    
    Args:
        username: The user's login name (uid)
        password: The user's password
        
    Returns:
        True if authentication succeeds, False otherwise
    """
    if not Config.LDAP_ENABLED:
        return False
    
    if not password:
        logger.debug("Empty password provided, rejecting LDAP auth")
        return False
    
    try:
        # Create server connection
        tls = None
        if Config.LDAP_USE_TLS:
            tls = Tls()
        
        server = Server(
            Config.LDAP_SERVER,
            use_ssl=Config.LDAP_SERVER.startswith('ldaps://'),
            tls=tls,
            get_info=ALL
        )
        
        # First, bind with service account to search for user
        bind_conn = None
        user_dn = None
        
        if Config.LDAP_BIND_DN and Config.LDAP_BIND_PASSWORD:
            # Use service account to search for user
            logger.debug(f"Connecting to LDAP server with bind DN: {Config.LDAP_BIND_DN}")
            bind_conn = Connection(
                server,
                user=Config.LDAP_BIND_DN,
                password=Config.LDAP_BIND_PASSWORD,
                auto_bind=True
            )
            
            if Config.LDAP_USE_TLS and not Config.LDAP_SERVER.startswith('ldaps://'):
                bind_conn.start_tls()
            
            # Search for the user
            search_filter = Config.LDAP_USER_FILTER.format(username)
            bind_conn.search(
                search_base=Config.LDAP_BASE_DN,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=[]  # DN is always returned, no extra attributes needed
            )
            
            if bind_conn.entries:
                user_dn = str(bind_conn.entries[0].entry_dn)
                logger.debug(f"Found user DN: {user_dn}")
            else:
                logger.debug(f"User '{username}' not found in LDAP")
                bind_conn.unbind()
                return False
            
            bind_conn.unbind()
        else:
            # No service account - construct user DN from template
            user_dn = Config.LDAP_USER_DN_TEMPLATE.format(username, Config.LDAP_BASE_DN)
            logger.debug(f"Using constructed user DN: {user_dn}")
        
        # Now attempt to bind as the user to verify password
        logger.debug(f"Attempting to authenticate user: {username}")
        user_conn = Connection(
            server,
            user=user_dn,
            password=password,
            auto_bind=True
        )
        
        if Config.LDAP_USE_TLS and not Config.LDAP_SERVER.startswith('ldaps://'):
            user_conn.start_tls()
        
        # If we get here, authentication succeeded
        logger.info(f"LDAP authentication successful for user: {username}")
        user_conn.unbind()
        return True
        
    except LDAPBindError as e:
        logger.debug(f"LDAP bind failed for user '{username}': {e}")
        return False
    except LDAPException as e:
        logger.error(f"LDAP error during authentication: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during LDAP authentication: {e}")
        return False

