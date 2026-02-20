"""SQLite database operations for whitelist entries."""
import sqlite3
import datetime
from typing import List, Dict, Any, Optional
from werkzeug.security import check_password_hash
from config import Config


def get_db_connection():
    """Get a database connection."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database and create tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create whitelist_entries table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist_entries (
            ip TEXT PRIMARY KEY,
            credential_id TEXT NOT NULL,
            auth_time TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    ''')
    
    # Create index on expires_at for efficient cleanup queries
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_expires_at 
        ON whitelist_entries(expires_at)
    ''')
    
    conn.commit()
    conn.close()


def verify_credential(credential_id: str, password: str) -> bool:
    """Verify a credential ID and password against environment configuration."""
    credentials = Config.get_credentials()
    
    if credential_id not in credentials:
        return False
    
    password_hash = credentials[credential_id]
    return check_password_hash(password_hash, password)


def add_whitelist_entry(ip: str, credential_id: str):
    """Add or update a whitelist entry."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(hours=Config.ENTRY_VALIDITY_HOURS)
    
    cursor.execute('''
        INSERT OR REPLACE INTO whitelist_entries 
        (ip, credential_id, auth_time, expires_at)
        VALUES (?, ?, ?, ?)
    ''', (ip, credential_id, now.isoformat(), expires_at.isoformat()))
    
    conn.commit()
    conn.close()
    
    # Cleanup after adding entry
    cleanup_expired_entries()
    enforce_max_entries()
    
    # Notify BunkerWeb of whitelist change (non-blocking)
    if Config.BUNKERWEB_ENABLED:
        import threading
        import bunkerweb
        thread = threading.Thread(
            target=bunkerweb.notify_whitelist_change,
            args=(ip, 'add'),
            daemon=True
        )
        thread.start()


def remove_whitelist_entry(ip: str) -> bool:
    """Remove a whitelist entry by IP address.
    
    Args:
        ip: IP address to remove from whitelist
        
    Returns:
        True if entry was removed, False if not found
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM whitelist_entries WHERE ip = ?', (ip,))
    removed = cursor.rowcount > 0
    
    conn.commit()
    conn.close()
    
    # Notify BunkerWeb of whitelist change (non-blocking)
    if removed and Config.BUNKERWEB_ENABLED:
        import threading
        import bunkerweb
        thread = threading.Thread(
            target=bunkerweb.notify_whitelist_change,
            args=(ip, 'remove'),
            daemon=True
        )
        thread.start()
    
    return removed


def check_ip_status(ip: str) -> Optional[Dict[str, Any]]:
    """Check if a specific IP is whitelisted and valid.
    
    Args:
        ip: IP address to check
        
    Returns:
        Dictionary with entry info if valid, None if not whitelisted or expired.
        Contains: ip, expires_at, remaining_seconds
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.datetime.utcnow()
    now_iso = now.isoformat()
    
    cursor.execute('''
        SELECT ip, expires_at
        FROM whitelist_entries
        WHERE ip = ? AND expires_at > ?
    ''', (ip, now_iso))
    
    row = cursor.fetchone()
    conn.close()
    
    if row is None:
        return None
    
    expires_at = datetime.datetime.fromisoformat(row['expires_at'])
    remaining_seconds = max(0, int((expires_at - now).total_seconds()))
    
    # Return expires_at with 'Z' suffix to indicate UTC
    expires_at_iso = expires_at.isoformat() + 'Z'
    
    return {
        'ip': row['ip'],
        'expires_at': expires_at_iso,
        'remaining_seconds': remaining_seconds
    }


def get_valid_ips() -> List[str]:
    """Get list of valid (non-expired) IP addresses."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute('''
        SELECT ip FROM whitelist_entries
        WHERE expires_at > ?
        ORDER BY ip
    ''', (now,))
    
    ips = [row['ip'] for row in cursor.fetchall()]
    conn.close()
    
    return ips


def get_all_whitelist_entries(valid_only: bool = True) -> List[Dict[str, Any]]:
    """Get all whitelist entries with full information.
    
    Args:
        valid_only: If True, only return non-expired entries. If False, return all entries.
    
    Returns:
        List of dictionaries containing entry information.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.datetime.utcnow()
    now_iso = now.isoformat()
    
    if valid_only:
        cursor.execute('''
            SELECT ip, credential_id, auth_time, expires_at
            FROM whitelist_entries
            WHERE expires_at > ?
            ORDER BY auth_time DESC
        ''', (now_iso,))
    else:
        cursor.execute('''
            SELECT ip, credential_id, auth_time, expires_at
            FROM whitelist_entries
            ORDER BY auth_time DESC
        ''')
    
    entries = []
    for row in cursor.fetchall():
        auth_time = datetime.datetime.fromisoformat(row['auth_time'])
        expires_at = datetime.datetime.fromisoformat(row['expires_at'])
        is_valid = expires_at > now
        
        entries.append({
            'ip': row['ip'],
            'credential_id': row['credential_id'],
            'auth_time': row['auth_time'],
            'expires_at': row['expires_at'],
            'is_valid': is_valid,
            'remaining_seconds': max(0, int((expires_at - now).total_seconds())) if is_valid else 0
        })
    
    conn.close()
    return entries


def cleanup_expired_entries():
    """Remove expired entries from the whitelist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    now = datetime.datetime.utcnow().isoformat()
    cursor.execute('DELETE FROM whitelist_entries WHERE expires_at <= ?', (now,))
    
    conn.commit()
    conn.close()


def enforce_max_entries():
    """Remove oldest entries if limit is exceeded."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Count current entries
    cursor.execute('SELECT COUNT(*) as count FROM whitelist_entries')
    count = cursor.fetchone()['count']
    
    if count > Config.MAX_ENTRIES:
        # Delete oldest entries
        excess = count - Config.MAX_ENTRIES
        cursor.execute('''
            DELETE FROM whitelist_entries
            WHERE ip IN (
                SELECT ip FROM whitelist_entries
                ORDER BY auth_time ASC
                LIMIT ?
            )
        ''', (excess,))
    
    conn.commit()
    conn.close()

