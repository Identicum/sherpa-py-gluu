import sys
import os
import base64
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.gluu.gluu_lib import OxTrustAPIClient

def encode_credentials(client_id, client_secret):
    """Encodes the client_id and client_secret to Base64."""
    creds = f"{client_id}:{client_secret}".encode("utf-8")
    return base64.b64encode(creds).decode("utf-8")

def execute_oxtrust_api_call_upsert(hostname, credentials, rest_endpoint, objects_path, logger):
    execute_oxtrust_api_call(hostname, credentials, "UPSERT", rest_endpoint, objects_path, logger)

def execute_oxtrust_api_call_update(hostname, credentials, rest_endpoint, objects_path, logger):
    execute_oxtrust_api_call(hostname, credentials, "UPDATE", rest_endpoint, objects_path, logger)

def execute_oxtrust_api_call(hostname, credentials, operation, rest_endpoint, objects_path, logger):
    OxTrustAPIClient("https://{}/identity/restv1/api/v1".format(hostname), credentials, logger=logger, is_gluu_45=True).do_bulk(operation, rest_endpoint, objects_path)

def main():

    local_properties = Properties("./local.properties", "./default.properties")
    logger = Logger(os.path.basename(__file__), local_properties.get("idp_deployment_log_level"), local_properties.get("idp_deployment_log_file"))

    # hostname
    hostname = local_properties.get("idp_hostname")

    # Encode credentials in Base64
    credentials = encode_credentials(local_properties.get("oxtrustapi_client_id"), local_properties.get("oxtrustapi_client_secret"))

    # objects-folder name
    objects_folder= local_properties.get("idp_deploy_objects_folder")

    # # ox-settings
    # execute_oxtrust_api_call_update(hostname, credentials, "configuration/settings", f"{objects_folder}/ox-settings/ox-settings.json", logger)
    #
    # # oxauth-settings
    # execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxauth/settings", f"{objects_folder}/oxauth-settings/oxauth-settings.json", logger)
    #
    # # oxtrust-settings
    # execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxtrust/settings", f"{objects_folder}/oxtrust-settings/oxtrust-settings.json", logger)

    # # scripts
    # execute_oxtrust_api_call_upsert(hostname, credentials, "configuration/scripts", f"{objects_folder}/scripts", logger)
    #
    # # scopes
    # execute_oxtrust_api_call_upsert(hostname, credentials, "scopes", f"{objects_folder}/scopes", logger)
    #
    # # attributes
    execute_oxtrust_api_call_upsert(hostname, credentials, "attributes", f"{objects_folder}/attributes", logger)
    #
    # # clients
    # execute_oxtrust_api_call_upsert(hostname, credentials, "clients", f"{objects_folder}/clients", logger)
    #
    # # passport-providers
    # execute_oxtrust_api_call_upsert(hostname, credentials, "passport/providers", f"{objects_folder}/passport-providers", logger)

    # SAMLTr
    # IDP-Initiated Flows


if __name__ == '__main__':
    main()
