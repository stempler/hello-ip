"""LDAP authentication module for alternative credential verification."""
import logging
from typing import Optional
from ldap3 import Server, Connection, ALL, SUBTREE, Tls
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.utils.dn import safe_dn
from config import Config

logger = logging.getLogger(__name__)


def _get_allowed_group_dn() -> Optional[str]:
    """Get the allowed group DN, constructing it if needed.
    
    Returns:
        The group DN if configured, None otherwise
    """
    if not Config.LDAP_ALLOWED_GROUP:
        return None
    
    group_value = Config.LDAP_ALLOWED_GROUP.strip()
    if not group_value:
        return None
    
    # If it already looks like a DN (contains '='), use it as-is
    if '=' in group_value:
        return group_value
    
    # Otherwise, construct DN from template
    return Config.LDAP_GROUP_DN_TEMPLATE.format(group_value, Config.LDAP_BASE_DN)


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
    
    # Check if group-based access control is enabled
    allowed_group_dn = _get_allowed_group_dn()
    if allowed_group_dn:
        # Group checking requires service account
        if not Config.LDAP_BIND_DN or not Config.LDAP_BIND_PASSWORD:
            logger.error(
                "LDAP_ALLOWED_GROUP is configured but LDAP_BIND_DN and/or "
                "LDAP_BIND_PASSWORD are not set. Group-based access control "
                "requires a service account."
            )
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
        # This is required if group checking is enabled, optional otherwise
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
                attributes=[]  # DN is always returned
            )
            
            if bind_conn.entries:
                user_dn = str(bind_conn.entries[0].entry_dn)
                logger.debug(f"Found user DN: {user_dn}")
                
                # Check group membership if required
                if allowed_group_dn:
                    # LLDAP may not support memberOf, so search the group's member attribute
                    # Try searching by CN first (more reliable in LLDAP)
                    group_cn = allowed_group_dn.split(',')[0].split('=')[1] if '=' in allowed_group_dn else allowed_group_dn
                    
                    # Search for group - filter by CN and objectClass to ensure we only get groups
                    # LLDAP uses groupOfNames for groups. We require objectClass filter for security
                    # to prevent matching non-group entries that might have the same CN.
                    bind_conn.search(
                        search_base=Config.LDAP_BASE_DN,
                        search_filter=f"(&(cn={group_cn})(objectClass=groupOfNames))",
                        search_scope=SUBTREE,
                        attributes=['*']  # Request all attributes
                    )
                    
                    if bind_conn.entries:
                        entry = bind_conn.entries[0]
                        user_in_group = False
                        
                        # Check member attribute (groupOfNames)
                        if hasattr(entry, 'member') and entry.member:
                            if hasattr(entry.member, 'values'):
                                member_list = list(entry.member.values)
                            elif isinstance(entry.member, list):
                                member_list = entry.member
                            else:
                                member_list = [entry.member]
                            
                            # Normalize DNs for comparison using RFC 4514 compliant normalization
                            # safe_dn() handles escaped characters, whitespace, and attribute type equivalence
                            normalized_user_dn = safe_dn(user_dn).lower()
                            normalized_members = [safe_dn(str(m)).lower() for m in member_list]
                            user_in_group = normalized_user_dn in normalized_members
                            logger.debug(f"Group member list: {normalized_members}, User DN: {normalized_user_dn}, Match: {user_in_group}")
                        
                        if not user_in_group:
                            logger.warning(
                                f"User '{username}' (DN: {user_dn}) is not a member of required group "
                                f"'{allowed_group_dn}'. Authentication denied."
                            )
                            bind_conn.unbind()
                            return False
                        logger.debug(f"User '{username}' is a member of required group '{allowed_group_dn}'")
                    else:
                        logger.warning(
                            f"Group '{allowed_group_dn}' (CN: {group_cn}) with objectClass=groupOfNames not found. "
                            f"If using a different LDAP server, you may need to configure a different group objectClass."
                        )
                        bind_conn.unbind()
                        return False
            else:
                logger.debug(f"User '{username}' not found in LDAP")
                bind_conn.unbind()
                return False
            
            bind_conn.unbind()
        else:
            # No service account - construct user DN from template
            user_dn = Config.LDAP_USER_DN_TEMPLATE.format(username, Config.LDAP_BASE_DN)
            logger.debug(f"Using constructed user DN: {user_dn}")
        
        # Group membership check was already performed above if group checking was enabled
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

