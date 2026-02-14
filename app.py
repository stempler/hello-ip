"""Main Flask application for IP whitelist authentication."""
import ipaddress
from flask import Flask, request, render_template, jsonify, Response, send_from_directory
from config import Config
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


@main_app.route(Config.BASE_PATH + '/auth', methods=['POST'])
def authenticate():
    """Authenticate user and add IP to whitelist."""
    data = request.get_json() or {}
    credential_id = data.get('credential_id', '').strip()
    password = data.get('password', '').strip()
    
    if not credential_id or not password:
        return jsonify({'error': 'Missing credential_id or password'}), 400
    
    # Verify credentials
    if not database.verify_credential(credential_id, password):
        return jsonify({'error': 'Invalid credentials'}), 403
    
    # Get and validate client IP
    client_ip = get_client_ip()
    if not validate_ip(client_ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    # Add to whitelist
    database.add_whitelist_entry(client_ip, credential_id)
    
    return jsonify({
        'message': 'Authentication successful',
        'ip': client_ip
    }), 200


@main_app.route('/health')
@main_app.route(Config.BASE_PATH + '/health')
def health():
    """Health check endpoint."""
    return jsonify({'status': 'healthy'}), 200


@main_app.route(Config.BASE_PATH + '/static/<path:filename>')
def static_files(filename):
    """Serve static files only under the configured base path."""
    import os
    return send_from_directory(os.path.join(main_app.root_path, 'static'), filename)


@internal_app.route('/whitelist.txt')
def get_whitelist():
    """Return text file with valid IP addresses, one per line."""
    valid_ips = database.get_valid_ips()
    content = '\n'.join(valid_ips) + '\n'
    return Response(content, mimetype='text/plain')


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

