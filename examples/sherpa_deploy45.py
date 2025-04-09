import sys
import glob
import os
import base64
import json
import mysql.connector
from ldif import LDIFParser
from sherpa.utils.basics import Properties
from sherpa.utils.basics import Logger
from sherpa.utils import os_cmd
from sherpa.gluu import gluu_lib
from sherpa.gluu.gluu_lib import OxTrustAPIClient
from io import BytesIO


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

def read_passport_config_from_database(host, port, user, password, database, table_name, logger):
    try:
        connection = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )
        cursor = connection.cursor(dictionary=True)
        query = f"SELECT * FROM {table_name}"
        cursor.execute(query)
        rows = cursor.fetchall()
        logger.debug(f"Reading from {database} table {table_name}")
        if cursor.rowcount > 0:
            return rows[0]['gluuPassportConfiguration']
    except mysql.connector.Error as err:
        logger.debug(f"Database error: {err}")
        return []
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logger.debug("MySQL connection closed")

def update_passport_config_to_database(host, port, user, password, database, table_name, new_configuration, logger):
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database
        )

        logger.debug(f"Updating gluuPassportConfiguration as :  {new_configuration}")
        cursor = connection.cursor()
        json_new_configuration = json.dumps(new_configuration, ensure_ascii=True)

        # Update the gluuPassportConfiguration column in the table
        query = f"UPDATE {table_name} SET gluuPassportConfiguration = %s"
        cursor.execute(query, (json_new_configuration,))

        # Commit the transaction
        connection.commit()

        logger.debug(f"Successfully updated gluuPassportConfiguration in {table_name}")
        return True

    except mysql.connector.Error as err:
        logger.debug(f"Database error: {err}")
        return False

    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            logger.debug("MySQL connection closed")

def add_authorization_params_to_gluu_configs(passport_configs, new_auth_param, logger):
    passport_configs_updated = json.loads(passport_configs)
    v_array = passport_configs_updated.get('v', [])
    if not v_array or len(v_array) == 0:
        raise ValueError("'v' array not found or empty in the JSON")

    # Parse the inner JSON string
    inner_json = json.loads(v_array[0])

    # Extract the authorizationParams array
    if 'idpInitiated' not in inner_json or 'authorizationParams' not in inner_json['idpInitiated']:
        raise ValueError("authorizationParams not found in the JSON structure")

    auth_params = inner_json['idpInitiated']['authorizationParams']

    if new_auth_param:
        for each_new_param in new_auth_param:
            auth_params.append(each_new_param)

    # Update the inner JSON with the modified authorizationParams
    inner_json['idpInitiated']['authorizationParams'] = auth_params

    # Convert the inner JSON back to a string
    updated_inner_json_string = json.dumps(inner_json)

    # Update the original 'v' array
    passport_configs_updated['v'] = [updated_inner_json_string]
    return passport_configs_updated

def extract_authorization_params(ldif_file, logger):
    logger.debug(f"Extracting from {ldif_file}")
    with open(ldif_file, 'r', encoding='utf-8') as ldif_content:
        parser = LDIFParser(BytesIO(ldif_content.read().encode('utf-8')))
        for dn, entry in parser.parse():
            if 'gluuPassportConfiguration' in entry:
                json_string = entry['gluuPassportConfiguration'][0]
                passport_config = json.loads(json_string)
                if 'idpInitiated' in passport_config and 'authorizationParams' in passport_config['idpInitiated']:
                    auth_params = passport_config['idpInitiated']['authorizationParams']
    return auth_params

def deploy_initiated_flows(host, port, db_user, db_pwd, db_name, ldif_file, logger):
    gluu_passport_configs_from_db = read_passport_config_from_database(host, port, db_user, db_pwd, db_name, "oxPassportConfiguration", logger)
    logger.debug(f"Current passport configs in DB : {gluu_passport_configs_from_db}")
    auth_parameters_from_ldif_files = extract_authorization_params(ldif_file,logger)
    logger.debug(f"Extracted params: f{auth_parameters_from_ldif_files}")
    alterd_gluu_configs = add_authorization_params_to_gluu_configs(gluu_passport_configs_from_db, auth_parameters_from_ldif_files, logger)
    logger.debug(alterd_gluu_configs)
    update_passport_config_to_database( host, port, db_user, db_pwd, db_name, "oxPassportConfiguration", alterd_gluu_configs, logger)

def prepare_scripts(script_json_folder, script_code_folder, logger):
    work_folder = "./work/scripts"
    logger.debug("Deleting old work files.")
    os_cmd.execute_in_bash(f"rm -f {work_folder}/*.json", logger)
    os_cmd.execute_in_bash(f"mkdir -p {work_folder}", logger)
    logger.debug("Copying scripts to work directory")
    os_cmd.execute_in_bash(f"/bin/cp -f {script_json_folder}/*.json {work_folder}", logger)

    for directory_entry in sorted(os.scandir(work_folder), key=lambda path: path.name):
        if directory_entry.is_file() and directory_entry.path.endswith(".json"):
            logger.debug("Processing file: {}", directory_entry.path)

            with open(directory_entry.path) as json_file:
                json_data = json.load(json_file)

            script_path = os.path.join(script_code_folder, f"{json_data.get('name')}.py")
            with open(script_path) as script_file:
                json_data["script"] = script_file.read()

            with open(directory_entry.path, 'w') as out_file:
                json.dump(json_data, out_file, indent=2)


def main():

    local_properties = Properties("./local.properties", "./default.properties")
    logger = Logger(os.path.basename(__file__), local_properties.get("idp_deployment_log_level"), local_properties.get("idp_deployment_log_file"))

    #hostname
    hostname = local_properties.get("deploy_idp_hostname")

    # Encode credentials in Base64
    credentials = encode_credentials(local_properties.get("deploy_oxtrustapi_client_id"), local_properties.get("deploy_oxtrustapi_client_secret"))

    # objects-folder name
    objects_folder = local_properties.get("deploy_idp_objects_folder")
    script_code_folder = local_properties.get("deploy_idp_script_code_folder")

    # get old and new gluu instances salts
    old_salt = local_properties.get("backup_idp_salt_value")
    new_salt = local_properties.get("deploy_idp_salt_value")

    # get db info
    db_host = local_properties.get("deploy_db_host")
    db_port = local_properties.get("deploy_db_port")
    db_user = local_properties.get("deploy_db_user")
    db_pwd = local_properties.get("deploy_db_pwd")
    db_name = local_properties.get("deploy_db_name")

    # ox-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/settings", f"{objects_folder}/ox-settings/ox-settings.json", logger)

    # oxauth-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxauth/settings", f"{objects_folder}/oxauth-settings/oxauth-settings.json", logger)

    # oxtrust-settings
    execute_oxtrust_api_call_update(hostname, credentials, "configuration/oxtrust/settings", f"{objects_folder}/oxtrust-settings/oxtrust-settings.json", logger)

    # attributes
    execute_oxtrust_api_call_upsert(hostname, credentials, "attributes", f"{objects_folder}/attributes", logger)

    # scripts
    prepare_scripts(f"{objects_folder}/scripts", script_code_folder, logger)
    execute_oxtrust_api_call_upsert(hostname, credentials, "configuration/scripts", "./work/scripts", logger)

    # scopes
    execute_oxtrust_api_call_upsert(hostname, credentials, "scopes", f"{objects_folder}/scopes", logger)

    # clients
    saltify_client_secrets(old_salt, new_salt, f"{objects_folder}/clients", logger)
    execute_oxtrust_api_call_upsert(hostname, credentials, "clients", "./work/clients", logger)

    # passport-providers
    # add scopes in API Requesting Party Client
    # https://gluu.org/auth/oxtrust.passportprovider.write
    # https://gluu.org/auth/oxtrust.passportprovider.read
    execute_oxtrust_api_call_upsert(hostname, credentials, "passport/providers", f"{objects_folder}/passport-providers", logger)

    # # SAMLTr
    # generate_saml_jsons(f"{objects_folder}/samltr", logger)
    # execute_oxtrust_api_call_upsert(hostname, credentials, "saml/tr", "./work/samltr", logger)
    # execute_oxtrust_api_call_upsert(hostname, credentials, "saml/tr/update-metadata", "./work/samltr", logger)

    # IDP-Initiated Flows
    deploy_initiated_flows(db_host, db_port, db_user, db_pwd, db_name, f"{objects_folder}/oxpassport-config/oxpassport.ldif", logger)


if __name__ == '__main__':
    main()
