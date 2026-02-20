"""BunkerWeb API integration for whitelist change notifications."""
import logging
import threading
import time
from typing import Optional, List, Dict, Any
from urllib.parse import quote
import requests
from requests.auth import HTTPBasicAuth
from config import Config

logger = logging.getLogger(__name__)

# Thread-safe token cache
_token_cache = {
    'token': None,
    'expires_at': None
}
_token_lock = threading.Lock()

# Lock for serializing API calls
_api_lock = threading.Lock()


def login() -> Optional[str]:
    """Authenticate with BunkerWeb API and get token.
    
    Returns:
        Token string if successful, None otherwise.
    """
    if not Config.BUNKERWEB_API_URL or not Config.BUNKERWEB_USERNAME or not Config.BUNKERWEB_PASSWORD:
        logger.warning("BunkerWeb API credentials not configured")
        return None
    
    try:
        auth_url = f"{Config.BUNKERWEB_API_URL}/auth"
        response = requests.post(
            auth_url,
            auth=HTTPBasicAuth(Config.BUNKERWEB_USERNAME, Config.BUNKERWEB_PASSWORD),
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        token = data.get('token')
        
        if not token:
            logger.error("BunkerWeb API login response missing 'token' field")
            return None
        
        logger.info("Successfully authenticated with BunkerWeb API")
        return token
        
    except requests.exceptions.RequestException as e:
        logger.error(f"BunkerWeb API login failed: {e}")
        return None
    except (KeyError, ValueError) as e:
        logger.error(f"BunkerWeb API login response parsing failed: {e}")
        return None


def get_token() -> Optional[str]:
    """Get valid BunkerWeb API token, refreshing if necessary.
    
    Returns:
        Token string if available, None otherwise.
    """
    with _token_lock:
        # Check if cached token is still valid (with 5 minute buffer)
        if _token_cache['token'] and _token_cache['expires_at']:
            if time.time() < _token_cache['expires_at'] - 300:  # 5 minute buffer
                return _token_cache['token']
        
        # Token expired or missing, get new one
        token = login()
        if token:
            # Cache token (assume 1 hour validity, adjust if API provides expiration)
            _token_cache['token'] = token
            _token_cache['expires_at'] = time.time() + 3600  # 1 hour default
            return token
        
        # Clear cache on failure
        _token_cache['token'] = None
        _token_cache['expires_at'] = None
        return None


def get_cache_info(plugin: str, job_name: str, token: str) -> Optional[List[Dict[str, Any]]]:
    """Retrieve cache file information from BunkerWeb API.
    
    Args:
        plugin: Job plugin name
        job_name: Job name
        token: Bearer token for authentication
        
    Returns:
        List of cache entries if successful, None otherwise.
    """
    try:
        cache_url = f"{Config.BUNKERWEB_API_URL}/cache"
        params = {
            'plugin': plugin,
            'job_name': job_name,
            'with_data': 'false'
        }
        
        headers = {
            "Authorization": f"Bearer {token}",
            "accept": "application/json"
        }
        
        response = requests.get(
            cache_url,
            params=params,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        
        # Check response structure
        if data.get('status') != 'success':
            logger.warning(f"BunkerWeb cache info response status: {data.get('status')}")
            return None
        
        cache_entries = data.get('cache', [])
        logger.info(f"Retrieved {len(cache_entries)} cache entries for {plugin}/{job_name}")
        return cache_entries
        
    except requests.exceptions.RequestException as e:
        logger.error(f"BunkerWeb cache info retrieval failed: {e}")
        return None
    except (KeyError, ValueError) as e:
        logger.error(f"BunkerWeb cache info response parsing failed: {e}")
        return None


def delete_cache_file(service: str, plugin: str, job_name: str, file_name: str, token: str) -> bool:
    """Delete a single cache file from BunkerWeb.
    
    Args:
        service: Service name (e.g., "global" or specific service)
        plugin: Job plugin name
        job_name: Job name
        file_name: Cache file name
        token: Bearer token for authentication
        
    Returns:
        True if successful, False otherwise.
        Note: 404 (file not found) is treated as success.
    """
    try:
        # URL encode path components to handle special characters
        service_encoded = quote(service, safe='')
        plugin_encoded = quote(plugin, safe='')
        job_name_encoded = quote(job_name, safe='')
        file_name_encoded = quote(file_name, safe='')
        
        cache_url = f"{Config.BUNKERWEB_API_URL}/cache/{service_encoded}/{plugin_encoded}/{job_name_encoded}/{file_name_encoded}"
        
        headers = {
            "Authorization": f"Bearer {token}"
        }
        
        response = requests.delete(
            cache_url,
            headers=headers,
            timeout=10
        )
        
        # 404 means file doesn't exist (already deleted or never existed) - treat as success
        if response.status_code == 404:
            logger.debug(f"Cache file not found (already deleted?): {service}/{plugin}/{job_name}/{file_name}")
            return True
        
        response.raise_for_status()
        logger.info(f"Successfully deleted cache file: {service}/{plugin}/{job_name}/{file_name}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"BunkerWeb cache file deletion failed for {service}/{plugin}/{job_name}/{file_name}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error deleting cache file: {e}")
        return False


def clear_cache(plugin: str, job_name: str) -> bool:
    """Clear all cache files for a BunkerWeb job.
    
    Args:
        plugin: Job plugin name
        job_name: Job name
        
    Returns:
        True if all deletions successful, False otherwise.
        Continues even if some deletions fail.
    """
    token = get_token()
    if not token:
        logger.error("Cannot clear BunkerWeb cache: no valid token")
        return False
    
    # Get cache information
    cache_entries = get_cache_info(plugin, job_name, token)
    if cache_entries is None:
        logger.warning("Failed to retrieve cache info, skipping cache clearing")
        return False
    
    if not cache_entries:
        logger.info(f"No cache files found for {plugin}/{job_name}")
        return True
    
    # Delete each cache file
    success_count = 0
    failure_count = 0
    
    for entry in cache_entries:
        service = entry.get('service', 'global')
        file_name = entry.get('file_name', '')
        
        if not file_name:
            logger.warning(f"Cache entry missing file_name, skipping: {entry}")
            failure_count += 1
            continue
        
        if delete_cache_file(service, plugin, job_name, file_name, token):
            success_count += 1
        else:
            failure_count += 1
    
    logger.info(f"Cache clearing completed: {success_count} deleted, {failure_count} failed")
    
    # Return True if at least some deletions succeeded, or if there were no files
    return success_count > 0 or failure_count == 0


def trigger_job(plugin: str, name: str) -> bool:
    """Trigger a BunkerWeb job.
    
    Args:
        plugin: Job plugin name
        name: Job name
        
    Returns:
        True if successful, False otherwise.
    """
    token = get_token()
    if not token:
        logger.error("Cannot trigger BunkerWeb job: no valid token")
        return False
    
    try:
        jobs_url = f"{Config.BUNKERWEB_API_URL}/jobs/run"
        payload = {
            "jobs": [
                {
                    "plugin": plugin,
                    "name": name
                }
            ]
        }
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        response = requests.post(
            jobs_url,
            json=payload,
            headers=headers,
            timeout=30
        )
        response.raise_for_status()
        
        logger.info(f"Successfully triggered BunkerWeb job: {plugin}/{name}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"BunkerWeb job trigger failed: {e}")
        # Token might be invalid, clear cache
        with _token_lock:
            _token_cache['token'] = None
            _token_cache['expires_at'] = None
        return False
    except Exception as e:
        logger.error(f"Unexpected error triggering BunkerWeb job: {e}")
        return False


def unban_ip(ip: str) -> bool:
    """Unban an IP address in BunkerWeb.
    
    Args:
        ip: IP address to unban
        
    Returns:
        True if successful, False otherwise.
    """
    token = get_token()
    if not token:
        logger.error("Cannot unban IP in BunkerWeb: no valid token")
        return False
    
    try:
        bans_url = f"{Config.BUNKERWEB_API_URL}/bans"
        payload = [{"ip": ip}]
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "accept": "application/json"
        }
        
        response = requests.delete(
            bans_url,
            json=payload,
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        
        logger.info(f"Successfully unbanned IP in BunkerWeb: {ip}")
        return True
        
    except requests.exceptions.RequestException as e:
        logger.error(f"BunkerWeb IP unban failed for {ip}: {e}")
        # Token might be invalid, clear cache
        with _token_lock:
            _token_cache['token'] = None
            _token_cache['expires_at'] = None
        return False
    except Exception as e:
        logger.error(f"Unexpected error unbanning IP {ip}: {e}")
        return False


def notify_whitelist_change(ip: Optional[str] = None, action: str = 'add') -> None:
    """Notify BunkerWeb of whitelist change by clearing cache and triggering configured job.
    
    Optionally unban the IP address if configured to do so (only on 'add' action).
    
    Args:
        ip: Optional IP address that was added/removed. If provided and unbanning is enabled,
            this IP will be unbanned after the job is triggered (only for 'add' action).
        action: The type of change - 'add' for new/extended entries, 'remove' for deletions.
            Unbanning only happens on 'add' action.
    
    This function is thread-safe and handles errors gracefully.
    It runs in a non-blocking manner and logs errors without raising exceptions.
    """
    if not Config.BUNKERWEB_ENABLED:
        return
    
    if not Config.BUNKERWEB_API_URL:
        logger.warning("BunkerWeb integration enabled but API URL not configured")
        return
    
    logger.info(f"BunkerWeb notification triggered for action '{action}' on IP: {ip}")
    
    # Use lock to serialize API calls and prevent concurrent conflicts
    with _api_lock:
        try:
            # First, clear cache files
            logger.info("Clearing BunkerWeb cache before triggering job")
            cache_cleared = clear_cache(Config.BUNKERWEB_JOB_PLUGIN, Config.BUNKERWEB_JOB_NAME)
            if not cache_cleared:
                logger.warning("Cache clearing had issues, but continuing with job trigger")
            
            # Then trigger the job
            success = trigger_job(Config.BUNKERWEB_JOB_PLUGIN, Config.BUNKERWEB_JOB_NAME)
            if not success:
                logger.warning("BunkerWeb job trigger failed, but continuing whitelist operation")
            
            # Optionally unban the IP if enabled, IP is provided, and action is 'add'
            if Config.BUNKERWEB_UNBAN_ENABLED and ip and action == 'add':
                logger.info(f"Unbanning IP in BunkerWeb: {ip}")
                unban_success = unban_ip(ip)
                if not unban_success:
                    logger.warning(f"BunkerWeb IP unban failed for {ip}, but continuing whitelist operation")
        except Exception as e:
            # Catch any unexpected errors to ensure whitelist operations continue
            logger.error(f"Unexpected error in BunkerWeb notification: {e}", exc_info=True)

