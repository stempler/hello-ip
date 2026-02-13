#!/usr/bin/env python3
"""Helper script to generate password hashes for the CREDENTIALS environment variable."""
import sys
import json
from werkzeug.security import generate_password_hash


def hash_password(password: str) -> str:
    """Generate a Werkzeug password hash."""
    return generate_password_hash(password)


def main():
    """Generate password hashes for credentials."""
    if len(sys.argv) < 2:
        print("Usage: python hash_password.py <password> [credential_id]")
        print("\nExamples:")
        print("  python hash_password.py mypassword")
        print("  python hash_password.py mypassword admin")
        print("\nTo generate a JSON object for CREDENTIALS env var:")
        print("  python hash_password.py mypassword admin")
        print("  python hash_password.py otherpass user1")
        print("  Then combine: {\"admin\": \"<hash1>\", \"user1\": \"<hash2>\"}")
        sys.exit(1)
    
    password = sys.argv[1]
    credential_id = sys.argv[2] if len(sys.argv) > 2 else None
    
    password_hash = hash_password(password)
    
    if credential_id:
        # Output as JSON object ready for CREDENTIALS env var
        result = {credential_id: password_hash}
        print(json.dumps(result))
    else:
        # Just output the hash
        print(password_hash)


if __name__ == '__main__':
    main()

