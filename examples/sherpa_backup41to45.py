"""
Gluu Backup Script (from 41 to 45)

This script performs backups of various Gluu Server configurations.

How it works:
- The user provides `hostname`, `client_id`, and `client_secret` as command-line arguments.
- The script encodes `client_id:client_secret` in Base64 for authentication.
- Optionally, the user can pass `--include-default` as a JSON dictionary to override include settings.

Usage:
    python sherpa_backup41to45.py --hostname <GLUU_HOST> --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET> [--include-default '{"scope": ["custom_scope1"], "script": ["custom_script1"]}']

Example:
    python sherpa_backup41to45.py --hostname my-gluu-server.com --client-id myclientid --client-secret myclientsecret --include-default '{"script": ["basic", "extra_script"]}'
"""

import sys
import base64
import argparse
import json
from sherpa.gluu.gluu_lib import GluuBackup

def encode_credentials(client_id, client_secret):
    """Encodes the client_id and client_secret to Base64."""
    creds = f"{client_id}:{client_secret}".encode("utf-8")
    return base64.b64encode(creds).decode("utf-8")

def main():
    user_include_defaults = {}
    parser = argparse.ArgumentParser(description="Backup Gluu data with optional include settings.")

    # Command line arguments
    parser.add_argument("--hostname", required=True, help="Hostname of the Gluu server")
    parser.add_argument("--client-id", required=True, help="Client ID for authentication")
    parser.add_argument("--client-secret", required=True, help="Client Secret for authentication")
    parser.add_argument("--include-default", type=str, help="JSON dictionary of include_default values")

    args = parser.parse_args()

    # Encode credentials in Base64
    credentials = encode_credentials(args.client_id, args.client_secret)

    # Parse optional include-default argument
    try:
        user_include_defaults = json.loads(args.include_default) if args.include_default else {}
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in --include-default")
        sys.exit(1)

    # Initialize backup with hostname and encoded credentials
    backup = GluuBackup(args.hostname, credentials)

    # Perform backups with optional include_default settings
    backup.backup("scope41to45", "scopes", include_default=user_include_defaults.get("scope", []))
    backup.backup("script41to45", "configuration/scripts", include_default=user_include_defaults.get("script", []))
    backup.backup("attribute41to45", "attributes", include_default=user_include_defaults.get("attribute", []))
    backup.backup("passportprovider41to45", "passport/providers", include_default=user_include_defaults.get("passportprovider", []))
    backup.backup("client41to45", "clients", include_default=user_include_defaults.get("client", []))

    # These backups do NOT have include_default
    backup.backup("oxAuthSettings41to45", "configuration/oxauth/settings")
    backup.backup("oxTrustSettings41to45", "configuration/oxtrust/settings")
    backup.backup("oxSettings41to45", "configuration/settings")

if __name__ == '__main__':
    main()
