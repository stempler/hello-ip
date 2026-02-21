"""Main Flask application for IP whitelist authentication."""
import ipaddress
import logging
import os
import sys
from flask import Flask, request, render_template, jsonify, Response, send_from_directory
from config import Config

# Configure logging to output to stderr (captured by gunicorn's error log)
# This must be done before importing modules that use logging
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr,
    force=True  # Override any existing configuration
)

import database


# Create Flask app instances with static files disabled (we'll serve them via custom route)
main_app = Flask(__name__, static_folder=None)
internal_app = Flask(__name__)


def get_client_ip() -> str:
    """Extract client IP address from request."""
    # Check for X-Forwarded-For header (for proxy/load balancer scenarios)
    if request.headers.get('X-Forwarded-For'):
        # Take the first IP in the chain
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    
    return ip


def validate_ip(ip: str) -> bool:
    """Validate that the string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@main_app.route('/')
@main_app.route(Config.BASE_PATH + '/')
def index():
    """Serve the authentication form."""
    # Pass base_path to template - it will always have a trailing slash from Config
    # or be '/' for root, so we can safely append paths
    return render_template('auth.html', base_path=Config.BASE_PATH)


@main_app.route(Config.BASE_PATH + '/status', methods=['GET'])
def get_status():
    """Get current IP's whitelist status."""
    client_ip = get_client_ip()
    if not validate_ip(client_ip):
        return jsonify({'entered': False}), 200
    
    status = database.check_ip_status(client_ip)
    if status:
        return jsonify({
            'entered': True,
            'expires_at': status['expires_at'],
            'remaining_seconds': status['remaining_seconds']
        }), 200
    else:
        return jsonify({'entered': False}), 200


@main_app.route(Config.BASE_PATH + '/auth', methods=['POST'])
def authenticate():
    """Authenticate user and add IP to whitelist."""
    data = request.get_json() or {}
    credential_id = data.get('credential_id', '').strip()
    password = data.get('password', '').strip()
    
    if not credential_id or not password:
        return jsonify({'error': 'Missing credential_id or password'}), 400
    
    # Security: Validate credential_id length and characters to prevent abuse
    # Reasonable limit to prevent DoS and injection attempts
    if len(credential_id) > 256:
        return jsonify({'error': 'credential_id too long'}), 400
    
    if len(password) > 1024:  # Reasonable password length limit
        return jsonify({'error': 'password too long'}), 400
    
    # Verify credentials
    if not database.verify_credential(credential_id, password):
        return jsonify({'error': 'Invalid credentials'}), 403
    
    # Get and validate client IP
    client_ip = get_client_ip()
    if not validate_ip(client_ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    # Add to whitelist
    database.add_whitelist_entry(client_ip, credential_id)
    
    # Get updated status to return
    status = database.check_ip_status(client_ip)
    
    response = {
        'message': 'Authentication successful',
        'ip': client_ip,
        'entered': True
    }
    
    if status:
        response['expires_at'] = status['expires_at']
        response['remaining_seconds'] = status['remaining_seconds']
    
    return jsonify(response), 200


@main_app.route(Config.BASE_PATH + '/leave', methods=['DELETE'])
def leave():
    """Remove client IP from whitelist."""
    client_ip = get_client_ip()
    if not validate_ip(client_ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    # Check if IP is currently whitelisted
    status = database.check_ip_status(client_ip)
    if not status:
        return jsonify({'error': 'IP not whitelisted'}), 404
    
    # Remove from whitelist
    removed = database.remove_whitelist_entry(client_ip)
    
    if removed:
        return jsonify({
            'message': 'Successfully left the matrix',
            'ip': client_ip
        }), 200
    else:
        return jsonify({'error': 'Failed to remove IP'}), 500


@main_app.route('/health')
@main_app.route(Config.BASE_PATH + '/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'}), 200


@main_app.route(Config.BASE_PATH + '/static/<path:filename>')
def static_files(filename):
    """Serve static files only under the configured base path."""
    import os
    # Security: Validate filename to prevent path traversal
    # Flask's send_from_directory should handle this, but we add explicit validation
    if '..' in filename or filename.startswith('/'):
        return jsonify({'error': 'Invalid filename'}), 400
    
    static_dir = os.path.join(main_app.root_path, 'static')
    # Ensure the requested file is within the static directory
    requested_path = os.path.normpath(os.path.join(static_dir, filename))
    static_dir_abs = os.path.abspath(static_dir)
    requested_abs = os.path.abspath(requested_path)
    if os.path.commonpath([requested_abs, static_dir_abs]) != static_dir_abs:
        return jsonify({'error': 'Invalid filename'}), 400
    
    return send_from_directory(static_dir, filename)


@internal_app.route('/whitelist.txt')
def get_whitelist():
    """Return text file with valid IP addresses, one per line."""
    valid_ips = database.get_valid_ips()
    content = '\n'.join(valid_ips) + '\n'
    return Response(content, mimetype='text/plain')


@internal_app.route('/whitelist.json')
def get_whitelist_json():
    """Return JSON with all whitelist entry information."""
    from flask import request
    
    # Check if 'all' query parameter is set to include expired entries
    valid_only = request.args.get('all', 'false').lower() != 'true'
    
    entries = database.get_all_whitelist_entries(valid_only=valid_only)
    
    return jsonify({
        'count': len(entries),
        'valid_only': valid_only,
        'entries': entries
    })


def main():
    """Initialize database and start both Flask applications."""
    # Ensure database directory exists
    import os
    db_dir = os.path.dirname(Config.DATABASE_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # Initialize database
    database.init_db()
    
    # Start internal app in a separate thread
    import threading
    internal_thread = threading.Thread(
        target=lambda: internal_app.run(
            host='0.0.0.0',
            port=Config.INTERNAL_PORT,
            debug=False
        ),
        daemon=True
    )
    internal_thread.start()
    
    # Start main app
    main_app.run(host='0.0.0.0', port=Config.MAIN_PORT, debug=False)


if __name__ == '__main__':
    main()

