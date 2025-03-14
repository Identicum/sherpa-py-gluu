import sys
import base64
import os
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
import json
from sherpa.gluu.gluu_lib import GluuBackup

def encode_credentials(client_id, client_secret):
    """Encodes the client_id and client_secret to Base64."""
    creds = f"{client_id}:{client_secret}".encode("utf-8")
    return base64.b64encode(creds).decode("utf-8")

def main():
    local_properties = Properties("./local.properties", "./default.properties")
    logger = Logger(os.path.basename(__file__), local_properties.get("idp_deployment_log_level"), local_properties.get("idp_deployment_log_file"))

    # hostname
    hostname = local_properties.get("idp_hostname")

    # Encode credentials in Base64
    credentials = encode_credentials(local_properties.get("oxtrustapi_client_id"), local_properties.get("oxtrustapi_client_secret"))

    backup_folder = local_properties.get("idp_backup_objects_folder")

    # Parse optional include-default argument
    try:
        user_include_defaults = json.loads(local_properties.get("idp_import_include_default"))
    except json.JSONDecodeError:
        logger.error("Error: Invalid JSON format in --include-default")
        sys.exit(1)

    # Initialize backup with hostname and encoded credentials
    backup = GluuBackup(hostname, credentials, logger, backup_folder)

    # Perform backups with optional include_default settings
    backup.backup("scope41to45", "scopes", user_include_defaults.get("scope", []))
    backup.backup("attribute41to45", "attributes", user_include_defaults.get("attribute", []))
    backup.backup("passportprovider41to45", "passport/providers", user_include_defaults.get("passportprovider", []))
    backup.backup("client41to45", "clients", user_include_defaults.get("client", []))

    # EncryptionService has changed its package, in 45 is org.gluu.oxauth.service.common, replace on script import sections
    backup.backup("script41to45", "configuration/scripts", user_include_defaults.get("script", []))

    # These backups do NOT have include_default
    backup.backup("oxAuthSettings41to45", "configuration/oxauth/settings")
    backup.backup("oxTrustSettings41to45", "configuration/oxtrust/settings")
    backup.backup("oxSettings41to45", "configuration/settings")

    # SAMLTr import
    # Get LDIF from LDAP:
    #    /opt/opendj/bin/ldapsearch -X -Z -D "cn=Directory Manager" -w <<PASSWORD>> -h localhost -p 1636  -b "ou=trustRelationships,o=gluu" "(objectClass=gluuSAMLconfig)" > trust_relationships.ldif
    # Get metadata files from SP (exclude credentials folder and idp-metadata.xml from backup):
    #    cp /opt/shibboleth-idp/metadata/*
    #
    # IDP-Initiated Flows Config
    #    /opt/opendj/bin/ldapsearch -X -Z -D "cn=Directory Manager" -w <<PASSWORD>> -h localhost -p 1636  -b "ou=oxpassport,ou=configuration,o=gluu" "(objectClass=oxPassportConfiguration)" > oxpassport.ldif
    # copy/paste the idpInitiated obj inside the oxpassport obj

if __name__ == '__main__':
    main()
