import sys
import os
import base64
import json
from ldif import LDIFParser
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.utils import os_cmd
from sherpa.gluu import gluu_lib
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

def saltify_client_secrets(old_salt, new_salt, clients_folder, logger):
    work_folder = "./work/clients"
    logger.debug("Deleting old work files.")
    os_cmd.execute_in_bash(f"rm -f {work_folder}/*.json", logger)
    os_cmd.execute_in_bash(f"mkdir -p {work_folder}", logger)
    logger.debug("Copying clients to work directory")
    os_cmd.execute_in_bash(f"/bin/cp -f {clients_folder}/*.json {work_folder}", logger)

    client_files = [f for f in os.listdir(work_folder) if f.endswith(".json")]
    logger.debug(f"Processing {len(client_files)} client files.")

    for client_file in client_files:
        file_path = os.path.join(work_folder, client_file)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                client_data = json.load(f)

            logger.debug(f"Processing client: {client_file}")
            plain_client_secret = str(gluu_lib.decode_with_gluu_salt(client_data.get("encodedClientSecret"), old_salt), 'utf-8')
            client_data['encodedClientSecret'] = gluu_lib.encode_with_gluu_salt(plain_client_secret, new_salt)

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(client_data, f, indent=4)
        except Exception as e:
            logger.error(f"Error processing {client_file}: {e}")

def get_attr(attributes, key, default=None, multi=False):
    if multi:
        return attributes.get(key, [])
    return attributes.get(key, [default])[0]

def generate_saml_jsons(samltr_folder, logger):
    samltr_ldif = f"{samltr_folder}/trust_relationships.ldif"
    work_folder = "./work/samltr"
    base_dn = "ou=trustRelationships,o=gluu"
    logger.debug("Deleting old work files.")
    os_cmd.execute_in_bash(f"rm -f {work_folder}/*.json", logger)
    os_cmd.execute_in_bash(f"mkdir -p {work_folder}", logger)
    logger.debug(f"Converting LDIF to JSON for Gluu 4.5 from {samltr_ldif}")

    with open(samltr_ldif, "rb") as f:
        parser = LDIFParser(f)
        for dn, attributes in parser.parse():
            if dn.endswith(base_dn) and dn != base_dn:
                logger.debug(f"Converting {dn} to JSON")
                inum = attributes["inum"][0]
                source_type =  get_attr(attributes, "gluuSAMLspMetaDataSourceType", "FILE").upper()

                tr_json = {
                    "displayName": get_attr(attributes, "displayName"),
                    "description": get_attr(attributes, "description"),
                    "entityType": "SingleSP",
                    "spMetaDataSourceType": source_type,
                    "spLogoutURL": get_attr(attributes,"oxAuthPostLogoutRedirectURI"),
                    "gluuSpecificRelyingPartyConfig": get_attr(attributes, "gluuSpecificRelyingPartyConfig"),
                    "releasedAttributes": get_attr(attributes, "gluuReleasedAttribute", multi=True),
                    "gluuIsFederation": get_attr(attributes, "gluuIsFederation"),
                    "gluuEntityId": get_attr(attributes, "gluuEntityId", multi=True),
                    "maxRefreshDelay": get_attr(attributes, "gluuSAMLmaxRefreshDelay"),
                    "status": get_attr(attributes, "gluuStatus", "ACTIVE").upper(),
                    "validationStatus": get_attr(attributes, "gluuValidationStatus", "SUCCESS").upper(),
                }

                if source_type == "URI":
                    tr_json["spMetaDataURL"] = get_attr(attributes,"gluuSAMLspMetaDataURL")
                elif source_type == "FILE":
                    tr_json["spMetaDataSourceType"] = "URI"
                    tr_json["spMetaDataURL"] = f"REPLACEME_{samltr_folder}/metadata-files/{inum}-sp-metadata.xml"
                else:
                    raise Exception("source_type_not_supported")

                json_path = f"{work_folder}/{inum}.json"
                with open(json_path, "w", encoding="utf-8") as f:
                    json.dump(tr_json, f, indent=4)
                logger.debug(f"Generated JSON: {json_path}")

def main():

    local_properties = Properties("./local.properties", "./default.properties")
    logger = Logger(os.path.basename(__file__), local_properties.get("idp_deployment_log_level"), local_properties.get("idp_deployment_log_file"))

    #hostname
    hostname = local_properties.get("deploy_idp_hostname")

    # Encode credentials in Base64
    credentials = encode_credentials(local_properties.get("deploy_oxtrustapi_client_id"), local_properties.get("deploy_oxtrustapi_client_secret"))

    # objects-folder name
    objects_folder = local_properties.get("deploy_idp_objects_folder")

    # get old and new gluu instances salts
    old_salt = local_properties.get("backup_idp_salt_value")
    new_salt = local_properties.get("deploy_idp_salt_value")

    # ox-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/settings", f"{objects_folder}/ox-settings/ox-settings.json", logger)

    # oxauth-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxauth/settings", f"{objects_folder}/oxauth-settings/oxauth-settings.json", logger)

    # oxtrust-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxtrust/settings", f"{objects_folder}/oxtrust-settings/oxtrust-settings.json", logger)

    # scripts
    execute_oxtrust_api_call_upsert(hostname, credentials, "configuration/scripts", f"{objects_folder}/scripts", logger)

    # scopes
    execute_oxtrust_api_call_upsert(hostname, credentials, "scopes", f"{objects_folder}/scopes", logger)

    # attributes
    execute_oxtrust_api_call_upsert(hostname, credentials, "attributes", f"{objects_folder}/attributes", logger)

    # clients
    saltify_client_secrets(old_salt, new_salt, f"{objects_folder}/clients", logger)
    execute_oxtrust_api_call_upsert(hostname, credentials, "clients", "./work/clients", logger)

    # passport-providers
    # add scopes in API Requesting Party Client
    # https://gluu.org/auth/oxtrust.passportprovider.write
    # https://gluu.org/auth/oxtrust.passportprovider.read
    execute_oxtrust_api_call_upsert(hostname, credentials, "passport/providers", f"{objects_folder}/passport-providers", logger)

    # SAMLTr
    generate_saml_jsons(f"{objects_folder}/samltr", logger)
    execute_oxtrust_api_call_upsert(hostname, credentials, "saml/tr", "./work/samltr", logger)
    execute_oxtrust_api_call_upsert(hostname, credentials, "saml/tr/update-metadata", "./work/samltr", logger)

    # IDP-Initiated Flows - Manual step
    # copy/paste the idpInitiated obj inside the oxpassport obj


if __name__ == '__main__':
    main()
