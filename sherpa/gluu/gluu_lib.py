# sherpa-py-gluu is available under the MIT License. https://github.com/Identicum/sherpa-py-gluu/
# Copyright (c) 2025, Identicum - https://identicum.com/
#
# Author: Gustavo J Gallardo - ggallard@identicum.com
#

import base64
import ldap
import ldap.dn
from ldap.dn import str2dn
import ldap.modlist
from ldif import LDIFParser, LDIFWriter
import json
import os
from os import listdir
from os.path import isfile, join, isdir
from pyDes import *
from sherpa.utils.clients import OIDCClient
from sherpa.utils.clients import UMAClient
from sherpa.utils import validators
from sherpa.utils.basics import Logger
from sherpa.utils import http
from sherpa.utils import os_cmd
import urllib3


########################################################################################################################
########## CLASSES #####################################################################################################
########################################################################################################################

class DefaultLDIFParser(LDIFParser):
    def __init__(self, input, logger=Logger("DefaultLDIFParser")):
        LDIFParser.__init__(self, input)
        self.entries = []
        self._logger = logger

    def handle(self, dn, entry):
        self._logger.debug("Appending dn: {}".format(dn))
        self.entries.append((dn, entry))


class Gluu3LDIFConvert(LDIFParser):
    def __init__(self, input, output, logger=Logger("Gluu3LDIFConvert")):
        LDIFParser.__init__(self, input)
        self._logger = logger
        self._writer = LDIFWriter(output, base64_attrs=None, cols=9999)

    def _get_string_values(self, entry, attribute_name):
        return list(map(lambda x: str(x, 'utf-8'), entry.get(attribute_name)))

    def _inum2uuid(self, inum):
        if len(inum) == 61 and inum.startswith("@!"):
            new_inum = "ffff7273-{}-{}-{}-{}{}{}".format(inum[27:31], inum[32:36], inum[42:46], inum[47:51],
                                                         inum[52:56], inum[57:61]).lower()
            self._logger.debug("Received inum: {}, returning new value: {}".format(inum, new_inum))
            return new_inum
        self._logger.debug("Returning original inum value: {}".format(inum))
        return inum

    def _remove_org_inum(self, dn):
        self._logger.debug("Removing org inum from dn: {}, type: {}", dn, type(dn))
        exploded_dn = ldap.dn.explode_dn(dn)
        dn_length = len(exploded_dn)
        self._logger.trace("exploded_dn: {}, type: {}, len: {}", exploded_dn, type(exploded_dn), dn_length)
        if dn_length > 1 and exploded_dn[dn_length - 1] == "o=gluu" and exploded_dn[dn_length - 2].startswith("o=@!"):
            exploded_dn.remove(exploded_dn[dn_length - 2])
        self._logger.trace("new exploded_dn: {}, type: {}, len: {}", exploded_dn, type(exploded_dn), dn_length)
        dn = ','.join(exploded_dn)
        return dn

    def handle(self, dn, entry):
        self._logger.info("Processing entry: {}", dn)
        self._logger.trace("Bypassing unneeded objects")
        if dn.startswith('ou=people'):
            self._logger.debug("Bypassing container object: {}".format(dn))
            return
        if entry.get('uid') and 'admin' in self._get_string_values(entry, 'uid'):
            self._logger.debug("Bypassing admin user: {}".format(dn))
            return
        if 'oxClientAuthorizations' in self._get_string_values(entry, 'objectClass'):
            self._logger.debug("Bypassing user consent: {}".format(dn))
            return
        self._logger.trace("Removing inum_org from DN")
        dn = self._remove_org_inum(dn)
        self._logger.trace("Processing inum in DN")
        exploded_dn = ldap.dn.explode_dn(dn)
        for index, dn_component in enumerate(exploded_dn):
            if dn_component.startswith('inum='):
                inum_value = exploded_dn[index][5:]
                exploded_dn[index] = 'inum=' + self._inum2uuid(inum_value)
        dn = ','.join(exploded_dn)
        self._logger.trace("Processing inum attribute in object")
        if entry.get('inum'):
            self._logger.trace("Processing inum_attr: {} with type: {}".format(entry['inum'], type(entry['inum'][0])))
            inum_value = entry['inum'][0].decode()
            self._logger.trace("inum_value: {}".format(inum_value))
            uuid_value = self._inum2uuid(inum_value)
            self._logger.trace("uuid_value: {}".format(uuid_value))
            if (inum_value != uuid_value):
                self._logger.debug("Replacing inum_value: {} with uuid_value: {}".format(inum_value, uuid_value))
                entry['inum'][0] = uuid_value.encode()
            if b'gluuPerson' in entry['objectClass']:
                self._logger.debug("Setting legacyInum in user object, with value: {}".format(inum_value))
                entry['legacyInum'] = []
                entry['legacyInum'].append(inum_value.encode())
        self._logger.debug("Processing USER objects")
        if b'gluuPerson' in entry['objectClass']:
            if entry.get('memberOf'):
                new_memberof_dns = []
                for groupDN in entry['memberOf']:
                    groupDN = groupDN.decode().lower()
                    self._logger.trace("groupDN: {}".format(groupDN))
                    new_groupDN = self._remove_org_inum(groupDN)
                    new_memberof_dns.append(new_groupDN.encode())
                entry['memberOf'] = new_memberof_dns
        self._logger.debug("Processing FIDO objects")
        if 'ou=fido' in exploded_dn:
            self._logger.debug("Processing FIDO: {}".format(dn))
        self._logger.debug("Writing entry")
        self._writer.unparse(dn, entry)


class Gluu4LDAP:
    def __init__(self, ldap_uri, ldap_username, ldap_password, logger=Logger("Gluu4LDAP")):
        self._logger = logger
        self._logger.debug("Connecting to: {}", ldap_uri)
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        self._ldap_conn = ldap.initialize(ldap_uri)
        self._logger.debug("Binding as: {}", ldap_username)
        self._ldap_conn.simple_bind_s(ldap_username, ldap_password)

    def get_object_attribute_values(self, object_dn, attribute_name):
        self._logger.info("Getting attribute: {} from object: {}", attribute_name, object_dn)
        ldap_result = self._ldap_conn.search_s(object_dn, ldap.SCOPE_BASE, "(objectclass=*)")
        self._logger.trace("ldap_result[0][1]: {}, type: {}", ldap_result[0][1], type(ldap_result[0][1]))
        ldap_attribute = ldap_result[0][1][attribute_name]
        self._logger.trace("ldap_attribute: {}, type: {}", ldap_attribute, type(ldap_attribute))
        return ldap_attribute

    def get_object_attribute_value(self, object_dn, attribute_name):
        return self.get_object_attribute_values(object_dn, attribute_name)[0].decode()

    def set_object_attribute(self, object_dn, attribute_name, attribute_value):
        self._logger.info("Setting attribute: {} with value: {}, in object: {}", attribute_name, attribute_value,
                          object_dn)
        old_value = {attribute_name: [self.get_object_attribute_value(object_dn, attribute_name)]}
        new_value = {attribute_name: [attribute_value.encode()]}
        self._logger.trace("old_value: {}, type: {}", old_value, type(old_value))
        self._logger.trace("new_value: {}, type: {}", new_value, type(new_value))
        modlist = ldap.modlist.modifyModlist(old_value, new_value)
        self._ldap_conn.modify_s(object_dn, modlist)

    def add_object(self, object_dn, attrs):
        self._logger.info("Adding object: {}", object_dn)
        modlist = ldap.modlist.addModlist(attrs)
        self._ldap_conn.add_s(object_dn, modlist)

    def import_ldif(self, ldif_fn):
        self._logger.info("Importing file: {}", ldif_fn)
        ldif_file = open(ldif_fn, "r")
        parser = DefaultLDIFParser(ldif_file, self._logger)
        parser.parse()
        for dn, entry in parser.entries:
            self._logger.debug("Processing dn: {}", dn)
            self._logger.debug("entry: {}, type: {}", entry, type(entry))
            try:
                self.add_object(dn, entry)
            except ldap.ALREADY_EXISTS:
                self._logger.info("object dn {} already exists", dn)
        self._logger.info("Finished processing LDIF file: {}", ldif_fn)


class Gluu4JSON:
    def __init__(self, logger=Logger("Gluu4JSON")):
        self._logger = logger

    def _get_key_from_dn(self, dn):
        dn_components = []
        for dn_component in str2dn(dn):
            for rd in dn_component:
                if rd[0] == 'o' and rd[1] == 'gluu':
                    continue
                dn_components.append(rd[1])
        dn_components.reverse()
        key = '_'.join(dn_components)
        # return "_" for "o=gluu"
        if not key:
            key = '_'
        return key

    def _get_attr_values(self, attr_name, attr_values):
        self._logger.trace("Getting attr values for attr: {}, attr_values: {}".format(attr_name, attr_values))
        # process ObjectClass
        if attr_name == "objectClass":
            if 'top' in attr_values:
                attr_values.remove('top')
            for attr_value in attr_values:
                if 'Custom' in attr_value and len(attr_values) > 1:
                    attr_values.remove(attr_value)
                if not 'gluu' in attr_value.lower() and len(attr_values) > 1:
                    attr_values.remove(attr_value)
            return attr_values[0]
        # process multi-valued string attributes
        if attr_name in ["memberOf"]:
            new_values = []
            for attr_value in attr_values:
                new_values.append(attr_value)
            return new_values
        # process single-valued numeric attributes
        if attr_name in ["oxCounter", "oxDeviceHashCode"]:
            return int(attr_values[0])
        # process single-valued datetime attributes
        if attr_name in ["creationDate", "createTimestamp", "oxAuthExpiration", "oxLastAccessTime"]:
            my_date_str = attr_values[0]
            self._logger.trace("my_date_str: {}", my_date_str)
            # 20201122112233.456Z  ->  2020-11-22T11:22:33.000000
            my_date = "{}-{}-{}T{}:{}:{}.000000".format(my_date_str[0:4], my_date_str[4:6], my_date_str[6:8],
                                                        my_date_str[8:10], my_date_str[10:12], my_date_str[12:14])
            self._logger.trace("my_date: {}", my_date)
            return my_date
        # process boolean attributes
        if attr_name in ["del"]:
            if attr_values[0] in ["true", "True", "TRUE"]:
                return True
            else:
                return False
        # by default, process attribute as single-valued string
        return attr_values[0]

    def get_documents_from_ldif(self, ldif_fn):
        self._logger.info("Processing file: {}".format(ldif_fn))
        ldif_file = open(ldif_fn, "rb")
        parser = DefaultLDIFParser(ldif_file)
        documents = []
        for dn, entry in parser.parse():
            self._logger.debug("Processing dn: {}".format(dn))
            self._logger.trace("entry: {}".format(entry))
            key = self._get_key_from_dn(dn)
            for attrKey in entry:
                entry[attrKey] = self._get_attr_values(attrKey, entry[attrKey])
            entry["dn"] = dn
            self._logger.trace("Processed key: {} entry: {}".format(key, entry))
            documents.append((key, entry))
        return documents


class OxTrustAPIClient:
    """
    oxTrustAPIClient simplifies functionality for oxTrust API interaction
    """

    def __init__(self, api_base_endpoint, b64_client_credentials, default_testing_endpoint_path="users",
                 logger=Logger("OxTrustAPIClient.py"), is_gluu_45=False):
        """
        Params
        :param api_base_endpoint: for instance "https://gluu.myorg.com/identity/restv1/api/v1"
        :param b64_client_credentials: 'client_id:client_secret' in base64 encoded format
        :param default_testing_endpoint_path: will be concatenated to api_base_endpoint, list can be found here -> https://gluu.org/docs/oxtrust-api
        :param logger: RoundServices log. If None, default will be created
        """
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.api_base_endpoint = api_base_endpoint
        self.default_testing_endpoint_path = default_testing_endpoint_path
        self.logger = logger
        self.uma_client = UMAClient(api_base_endpoint, b64_client_credentials, logger, verify=False, is_gluu_45=is_gluu_45)
        self.validate_api()

    def validate_api(self):
        """
        Validate if API is working properly asking for a RPT ticket to the default endpoint
        :return: True if response is not None, False if it is. Otherwise it will raise an error (Connectivity or permission problems for instance)
        """
        return self.uma_client.get_rpt(self.default_testing_endpoint_path) is not None

    def create(self, endpoint, json_obj):
        """
        CREATE object
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param json_obj: dict that represents object to be created
        :return: dict that represents created json obj
        """
        return self.uma_client.post(endpoint, json_obj)

    def delete(self, endpoint, json_obj):
        """
        DELETE object form API
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param json_obj: dict that represents object to be deleted with inum
        :return: dict. json_obj from input
        """
        self.uma_client.delete("{}/{}".format(endpoint, json_obj['inum']))
        return json_obj

    def update(self, endpoint, json_obj):
        """
        PUT object with json_obj values (Erase previous, so put all values needed xD)
        Configuration endpoints are the only ones that GET previous config and update only values from json_obj
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param json_obj: json_obj that contains changes to be applied
        :return: dict. json obj with new values applied. empty dict for attribute endpoint
        """
        config_endpoints = ["configuration/oxauth/settings",
                            "configuration/oxtrust/settings",
                            "configuration/settings",
                            "configuration/ldap",
                            "configuration/smtp",
                            "passport/config",
                            "acrs"
                            ]
        available_endpoints = {
            'attributes': 'attributes',
            'clients': 'clients',
            'scopes': 'scopes',
            'configuration/scripts': 'scripts',
            'passport/providers': 'passport/providers',
            'saml/tr/update': 'saml/tr/update'
        }
        if endpoint in config_endpoints:
            current_obj = self.uma_client.execute("GET", endpoint)
            self.logger.debug("Obtained object from HTTP GET: {}", current_obj)
            if endpoint == "configuration/ldap":
                current_obj = current_obj[0]
            for key, value in json_obj.items():
                current_obj[key] = value
        elif endpoint in available_endpoints:
            if endpoint not in ['passport/providers', 'saml/tr/update']:
                dn = "inum={},ou={},o=gluu".format(json_obj['inum'], available_endpoints[endpoint])
                self.logger.debug("adding dn for update: {}", dn)
                json_obj['dn'] = dn
            if endpoint == 'saml/tr/update':
                endpoint = "{}/{}".format(endpoint, json_obj.get('inum'))
            current_obj = json_obj
        else:
            validators.raise_and_log(self.logger, ValueError, "operation endpoint {} is not supported for update",
                                     endpoint)
        self.logger.debug("Modified object before HTTP PUT: {}", json.dumps(current_obj))
        response_body = self.uma_client.put(endpoint, current_obj)
        self.logger.debug("response after HTTP PUT: {}", response_body)
        return response_body

    def upsert(self, endpoint, json_obj):
        """
        Upsert based on UPDATE and GET rules
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param json_obj: json_obj that contains changes to be applied
        :return: dict. json obj
        """
        key = 'inum'
        if endpoint == 'passport/providers':
            key = 'id'
            inum = json_obj[key]
        elif 'saml/tr' in endpoint:
            inum = "fake_value"
        else:
            inum = json_obj[key]
        if inum is None:
            return self.create(endpoint, json_obj)
        try:
            if 'saml/tr' in endpoint:
                self.logger.debug("SAML Upsert requested, getting values from displayName attr")
                tr_list = self.uma_client.execute("GET", "saml/tr/list")
                self.logger.debug("looking for displayName: {}", json_obj['displayName'])
                self.logger.debug("current TRs are: {}", tr_list)
                tr_list = [tr for tr in tr_list if tr.get('displayName') == json_obj['displayName']]
                self.logger.debug("filtered list is {}", tr_list)
                tr_list_size = len(tr_list)
                if tr_list_size == 0:
                    self.logger.debug("create a new tr with given values")
                    return self.create("saml/tr/create", json_obj)
                elif tr_list_size == 1:
                    self.logger.debug("update a existing tr")
                    inum = tr_list[0].get('inum')
                    if "saml/tr/update-metadata" in endpoint:
                        file_name = json_obj.get("spMetaDataURL")
                        self.logger.debug("checking saml/tr/update-metadata with {}", file_name)
                        if file_name.startswith("REPLACEME_"):
                            file_path = file_name.split("REPLACEME_")[1]
                            self.logger.debug("file_path to extract xml is {}", file_path)
                            with open(file_path, "r", encoding="utf-8") as f:
                                xml_obj = f.read()
                                return self.post_samltr_raw_metadata(inum, xml_obj)
                        else:
                            self.logger.debug("No action to perform with {}", file_name)
                    else:
                        json_obj['inum'] = inum
                        json_obj['dn'] = "inum={},ou=trustRelationships,o=gluu".format(inum)
                        return self.update("saml/tr/update", json_obj)
                else:
                    validators.raise_and_log(self.logger, ValueError, "duplicated displayName obj for Trust relationship, stopped UPSERT operation", endpoint)
            else:
                response = self.get_by_inum(endpoint, json_obj, key)
                self.logger.debug("get_by_inum for update operation result is: {}", response)
            if isinstance(response, dict) and ('inum' in response or 'id' in response):
                self.logger.debug("Updating object with inum: {}", inum)
                return self.update(endpoint, json_obj)
            else:
                return self.create(endpoint, json_obj)
        except IOError:
            self.logger.debug("Object does not exist, lets create it...")
            return self.create(endpoint, json_obj)

    def post_samltr_raw_metadata(self, inum, xml_obj):
        response = self.uma_client.post_samltr_raw_metadata(inum, xml_obj)
        self.logger.debug("set_metadata endpoint response: {}", response)
        return response

    def get_by_inum(self, endpoint, json_obj, key='inum'):
        """
        GET operation with object inum
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param json_obj: from required object (with inum)
        :return: dict. represent json. otherwise raise error value.
        """
        inum = json_obj[key]
        self.logger.debug("""
        GET operation with params:
        endpoint: {}
        inum: {}
        """, endpoint, inum)
        rpt = None
        if endpoint == 'attributes':
            url = '{}/attribute/{}'.format(endpoint, inum)
            rpt = self.uma_client.get_rpt(url)
        response = self.uma_client.get('{}/{}'.format(endpoint, inum)) if rpt is None else self.uma_client.execute(
            "GET", url, rpt=rpt)
        self.logger.debug("JSON Response: {}", response)
        return response

    def get(self, endpoint):
        """
        GET operation with no validation
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :return: dict. represent json. otherwise raise error value.
        """
        self.logger.debug("""
        GET operation with params:
        endpoint: {}
        """, endpoint)
        response = self.uma_client.get('{}'.format(endpoint))
        self.logger.debug("JSON Response: {}", response)
        return response

    def do_bulk(self, operation, endpoint, path):
        """
        Do named operation with a file/folder which has json files.
        Stops execution if one operation fails
        :param operation: operation to execute in bulk (CREATE/UPDATE/DELETE/UPSERT/GET_BY_INUM)
        :param endpoint: from oxTrustAPI for instance attributes, clients, configuration/scripts
        :param path: path to the file/folder with json files
        """
        function = self._get_operation(operation)
        json_array = self._load_bulk_json(path)
        total = len(json_array)
        self.logger.info("Starting bulk operation {} for {} objects in {} endpoint", operation, total, endpoint)
        for json_obj in json_array:
            function(endpoint, json_obj)
        self.logger.info("{} objects have been processed OK", total)

    def _get_operation(self, operation):
        if operation == 'CREATE':
            return self.create
        elif operation == 'UPDATE':
            return self.update
        elif operation == 'DELETE':
            return self.delete
        elif operation == 'GET_BY_INUM':
            return self.get_by_inum
        elif operation == 'UPSERT':
            return self.upsert
        else:
            validators.raise_and_log(self.logger, AttributeError,
                                     "OxTrust Deployer - Operation required does not exist")

    def _load_bulk_json(self, path):
        """ Load json files from a folder or a single json file
        :param path: path to the json folder/file
        :return: list with JSON objects (dict)
        """
        files_path = [path] if not isdir(path) else [join(path, f) for f in listdir(path) if
                                                     isfile(join(path, f)) and f.endswith(".json")]
        json_to_process = []
        error_msg = 'File content is not a JSON obj/array'
        self.logger.trace("Loading JSON list for bulk action with file paths: {}", files_path)
        for file_path in files_path:
            with open(file_path) as f:
                try:
                    data = f.read().replace('\n', '')
                    val = json.loads(data)
                    if isinstance(val, list):
                        json_to_process += val
                    elif isinstance(val, dict):
                        json_to_process.append(val)
                    else:
                        validators.raise_and_log(self.logger, TypeError, error_msg)
                except ValueError:
                    validators.raise_and_log(self.logger, TypeError, error_msg)
        self.logger.trace("Loaded JSON is: {}", json_to_process)
        return json_to_process


class GluuTransformer:
    """Converts Gluu API objects to JSON"""

    DEFAULT_MAIN_PATH = "./backup"

    def __init__(self, source_json, main_path=None, logger=Logger("GluuTransformer.py")):
        self.data = source_json
        self.logger = logger
        self.main_path = main_path if main_path else self.DEFAULT_MAIN_PATH

    def subfolder(self):
        self.logger.error("each subclass must define a subfolder")
        raise NotImplementedError("each subclass must define a subfolder")

    def id_attr(self):
            self.logger.error("each subclass must define an id_attr")
            raise NotImplementedError("each subclass must define an id_attr")

    def map_single_attrs(self, attribute_map):
        """
        Maps single-value attributes from the source JSON based on a mapping dictionary.

        :param attribute_map: Dictionary where keys are source attributes and values are target attributes.
        """
        transformed_data = {}
        for old_attr, new_attr in attribute_map.items():
            transformed_data[new_attr] = self.data.get(old_attr)
        return transformed_data

    def default_objs(self):
        self.logger.error("each subclass must define a default_objs")
        raise NotImplementedError("each subclass must define a default_objs")

    def map_list_attrs(self, list_attributes):
        """
        Maps list-type attributes, ensuring they are always lists.

        :param list_attributes: List of attributes that should be treated as lists.
        """
        transformed_data = {}
        for attr in list_attributes:
            transformed_data[attr] = self.data.get(attr, [])
        return transformed_data

    def transform(self):
        """Implemented by each subclass to convert JSON"""
        self.logger.error("transform() method must be implemented by subclass")
        raise NotImplementedError("transform() method must be implemented by subclass")

    def save_to_file(self, filename):
        """Saves converted JSON to a file"""
        folder_path = os.path.join(self.main_path, self.subfolder())
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, filename)

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=4)

        self.logger.debug(f"file saved: {file_path}")


class Scope41to45Transformer(GluuTransformer):
    """Scope transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "scopes"

    def id_attr(self):
        return "id"

    def default_objs(self):
        return [
            "address", "clientinfo", "email", "mobile_phone", "monitoring", "openid", "oxd", "permission",
            "phone", "profile", "super_gluu_ro_session", "uma_protection", "user_name"
            ]

    def transform(self):
        transformed_data = self.map_single_attrs({
            "dn": "dn",
            "inum": "inum",
            "displayName": "displayName",
            "id": "id",
            "description": "description",
            "scopeType": "scopeType",
            "defaultScope": "defaultScope",
            "oxAuthGroupClaims": "oxAuthGroupClaims",
            "umaAuthorizationPolicies": "umaAuthorizationPolicies"
        })
        transformed_data.update(self.map_list_attrs([ "oxAuthClaims", "dynamicScopeScripts" ]))
        self.data = transformed_data
        return self

class Script41to45Transformer(GluuTransformer):
    """Script transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "scripts"

    def id_attr(self):
            return "name"

    def default_objs(self):
        return [
            "application_session", "basic", "basic_lock", "cache_refresh", "cert", "client_registration",
            "consent_gathering", "duo", "dynamic_permission", "fido2", "id_generator", "introspection_custom_params",
            "introspection_sample", "monitoring", "org_name", "otp", "oxtrust_api_access_policy", "passport_saml",
            "passport_social", "reset_passwords", "resource_owner_password_credentials_custom_params_example",
            "resource_owner_password_credentials_example", "sampleClaimsGathering", "scim_access_policy",
            "scim_event_handler", "smpp", "super_gluu", "super_gluu_ro", "super_gluu_ro_session", "thumb_sign_in",
            "twilio_sms", "u2f", "uaf", "uma_rpt_policy", "update_user", "user_confirm_registration",
            "user_registration", "work_phone", "yubicloud"
            ]

    def transform(self):
        transformed_data = self.map_single_attrs({
                    "dn": "dn",
                    "inum": "inum",
                    "name": "name",
                    "description": "description",
                    "script": "script",
                    "scriptType": "scriptType",
                    "programmingLanguage": "programmingLanguage",
                    "enabled": "enabled",
                })
        transformed_data.update(self.map_list_attrs([ "moduleProperties", "configurationProperties" ]))
        self.data = transformed_data
        return self

class PassportProvider41to45Transformer(GluuTransformer):
    """PassportProvider transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "passport-providers"

    def id_attr(self):
            return "id"

    def default_objs(self):
        return []

    def transform(self):
        transformed_data = self.map_single_attrs({
                    "id": "id",
                    "displayName": "displayName",
                    "type": "type",
                    "mapping": "mapping",
                    "passportStrategyId": "passportStrategyId",
                    "enabled": "enabled",
                    "callbackUrl": "callbackUrl",
                    "requestForEmail": "requestForEmail",
                    "emailLinkingSafe": "emailLinkingSafe",
                    "options": "options",
                })

        # Extra rule for saml providers
        if transformed_data.get("type") == "saml":
            options = transformed_data.get("options") or {}
            options["wantAssertionsSigned"] = "false"
            transformed_data["options"] = options

        self.data = transformed_data
        return self

class Attribute41to45Transformer(GluuTransformer):
    """attribute transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "attributes"

    def id_attr(self):
            return "name"

    def default_objs(self):
        return [
            "address", "birthdate", "c", "carLicense", "cn", "departmentNumber", "description", "displayName",
            "eduPersonAffiliation", "eduPersonAssurance", "eduPersonEntitlement", "eduPersonNickName",
            "eduPersonOrcid", "eduPersonOrgDN", "eduPersonOrgUnitDN", "eduPersonPrimaryAffiliation",
            "eduPersonPrimaryOrgUnitDN", "eduPersonPrincipalName", "eduPersonPrincipalNamePrior",
            "eduPersonScopedAffiliation", "eduPersonTargetedID", "eduPersonUniqueId", "emailVerified",
            "employeeNumber", "employeeType", "facsimileTelephoneNumber", "gender", "givenName", "gluuIMAPData",
            "gluuStatus", "homePostalAddress", "iname", "inum", "l", "locale", "mail", "manager", "memberOf",
            "middleName", "mobile", "nickname", "o", "oxEnrollmentCode", "persistentId", "phoneNumberVerified",
            "picture", "postalCode", "postOfficeBox", "preferredDeliveryMethod", "preferredLanguage",
            "preferredUsername", "profile", "role", "roomNumber", "secretAnswer", "secretary", "secretQuestion",
            "sn", "st", "street", "telephoneNumber", "title", "transientId", "uid", "updatedAt",
            "userCertificate", "userPassword", "website", "zoneinfo"
            ]

    def transform(self):
        transformed_data = self.map_single_attrs({
                    "dn": "dn",
                    "inum": "inum",
                    "name": "name",
                    "displayName": "displayName",
                    "description": "description",
                    "oxAuthClaimName": "oxAuthClaimName",
                    "saml1Uri": "saml1Uri",
                    "saml2Uri": "saml2Uri",
                    "oxMultiValuedAttribute": "oxMultiValuedAttribute",
                    "origin": "origin",
                    "oxSCIMCustomAttribute": "oxSCIMCustomAttribute",
                    "dataType": "dataType",
                    "selected": "selected",
                    "custom": "custom",
                    "requred": "requred",
                    "status": "status"
                })
        transformed_data.update(self.map_list_attrs([ "usageType", "viewType", "editType", "attributeValidation" ]))
        self.data = transformed_data
        return self

class Client41to45Transformer(GluuTransformer):
    """Client transformer between Gluu 4.1 and 4.5."""

    def subfolder(self):
        return "clients"

    def id_attr(self):
        return "displayName"

    def default_objs(self):
        return [
            "API Requesting Party Client", "API Resource Server Client", "Gluu RO OpenID Client", "IDP client",
            "oxTrust Admin GUI", "Passport IDP-initiated flow Client", "Passport Requesting Party Client",
            "Passport Resource Server Client", "SCIM Requesting Party Client", "SCIM Resource Server Client"
            ]

    def transform(self):
        """Transforms the client data using the mapping functions."""
        transformed_data = self.map_single_attrs({
            "dn": "dn",
            "accessTokenAsJwt": "accessTokenAsJwt",
            "accessTokenLifetime": "accessTokenLifetime",
            "accessTokenSigningAlg": "accessTokenSigningAlg",
            "description": "description",
            "displayName": "displayName",
            "encodedClientSecret": "encodedClientSecret",
            "idTokenSignedResponseAlg": "idTokenSignedResponseAlg",
            "initiateLoginUri": "initiateLoginUri",
            "inum": "inum",
            "jwks": "jwks",
            "logoUri": "logoUri",
            "oxAuthAppType": "oxAuthAppType",
            "oxAuthPersistClientAuthorizations": "oxAuthPersistClientAuthorizations",
            "oxAuthTrustedClient": "oxAuthTrustedClient",
            "oxIncludeClaimsInIdToken": "oxIncludeClaimsInIdToken",
            "oxRefreshTokenLifetime": "oxRefreshTokenLifetime",
            "requireAuthTime": "requireAuthTime",
            "subjectType": "subjectType",
            "tokenEndpointAuthMethod": "tokenEndpointAuthMethod",
            "attributes": "attributes"
        })

        transformed_data.update(self.map_list_attrs([
            "defaultAcrValues",
            "grantTypes",
            "oxAuthPostLogoutRedirectURIs",
            "oxAuthRedirectURIs",
            "oxAuthScopes",
            "responseTypes"
        ]))

        self.data = transformed_data
        return self

class OxAuthSettings41to45(GluuTransformer):
    """oxauthsettings transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "oxauth-settings"

    def id_attr(self):
            return "oxauth-settings"

    def default_objs(self):
        return []

    def transform(self):
        transformed_data = self.data

        keys_to_remove = oxauth_configuration_keys = [
           "issuer", "baseEndpoint", "authorizationEndpoint", "tokenEndpoint", "tokenRevocationEndpoint",
           "userInfoEndpoint", "clientInfoEndpoint", "checkSessionIFrame", "endSessionEndpoint", "jwksUri",
           "registrationEndpoint", "openIdDiscoveryEndpoint", "openIdConfigurationEndpoint", "idGenerationEndpoint",
           "introspectionEndpoint", "umaConfigurationEndpoint", "oxElevenGenerateKeyEndpoint", "oxElevenSignEndpoint",
           "oxElevenVerifySignatureEndpoint", "oxElevenDeleteKeyEndpoint", "openidSubAttribute", "oxId",
           "pairwiseIdType", "pairwiseCalculationKey", "pairwiseCalculationSalt",
           "shareSubjectIdBetweenClientsWithSameSectorId", "webKeysStorage", "dnName", "keyStoreFile",
           "keyStoreSecret", "fido2Configuration"
       ]


        self.data = {key: value for key, value in transformed_data.items() if key not in keys_to_remove}
        return self

class OxTrustSettings41to45(GluuTransformer):
    """oxtrustsettings transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "oxtrust-settings"

    def id_attr(self):
        return "oxtrust-settings"

    def default_objs(self):
        return []

    def transform(self):
        transformed_data = self.data
        self.data = transformed_data
        return self

class OxSettings41to45(GluuTransformer):
    """oxsettings transformer between Gluu 4.1 y 4.5."""

    def subfolder(self):
        return "ox-settings"

    def id_attr(self):
        return "ox-settings"

    def default_objs(self):
        return []

    def transform(self):
        transformed_data = self.data
        self.data = transformed_data
        return self

class GluuBackup:
    """Handles backing up Gluu data, transforming it, and saving it to files."""

    def __init__(self, hostname, credentials, logger=Logger("GluuTransformer.py"), output_path=None):
        """
        Initializes the Gluu API client.
        :param hostname: Base URL of the Gluu server.
        :param credentials: Authentication token.
        """
        self.logger = logger
        self.output_path = output_path
        self.api_client = OxTrustAPIClient(f"https://{hostname}/identity/restv1/api/v1", credentials, logger=logger)

    def backup(self, entity_type, endpoint, include_default=[]):
        """
        Fetches data from an API endpoint, transforms it, and saves it to files.
        :param entity_type: The type of entity to back up (scope, attribute, script).
        :param endpoint: The API endpoint (e.g., "scopes").
        :param output_path: The directory where files will be saved (optional).
        """
        self.logger.debug(f"Fetching data from endpoint: {endpoint}...")
        entities = self.api_client.get(endpoint)  # API request

        if not entities:
            self.logger.debug(f"No data found at {endpoint}.")
            return

        if isinstance(entities, dict):
            entities = [entities]

        for entity in entities:
            transformer = get_transformer(entity_type, entity, self.output_path)
            file_attr_name = transformer.id_attr()
            if file_attr_name in ["oxauth-settings", "oxtrust-settings", "ox-settings"]:
                file_name = f"{file_attr_name}.json"
                transformer.transform().save_to_file(file_name)
            else:
                entity_id = entity.get(file_attr_name)
                if entity_id not in (set(transformer.default_objs()) - set(include_default)):
                    file_name = f"{entity_id}.json"
                    transformer.transform().save_to_file(file_name)

        self.logger.debug(f"{len(entities)} items backed up to {self.output_path or 'backup'}.")


########################################################################################################################
########## FUNCTIONS ###################################################################################################
########################################################################################################################

def get_transformer(type_name, json_data, main_path=None):
    """Returns transform"""
    transformers = {
        "scope41to45": Scope41to45Transformer,
        "script41to45": Script41to45Transformer,
        "attribute41to45": Attribute41to45Transformer,
        "passportprovider41to45": PassportProvider41to45Transformer,
        "client41to45": Client41to45Transformer,
        "oxAuthSettings41to45": OxAuthSettings41to45,
        "oxTrustSettings41to45": OxTrustSettings41to45,
        "oxSettings41to45": OxSettings41to45
    }
    transformer_class = transformers.get(type_name, GluuTransformer)
    return transformer_class(json_data, main_path)


def test_oxtrust_api(idp_url, client_id, client_secret, logger):
    logger.info("Testing oxTrust API configuration")
    logger.info("Checking access to IDP (oxauth, oxtrust)")
    http.wait_for_endpoint("{}/.well-known/openid-configuration".format(idp_url), 10, 30, logger)
    http.wait_for_endpoint("{}/.well-known/scim-configuration".format(idp_url), 10, 30, logger)
    oidc_client = OIDCClient(idp_url, logger)
    http.wait_for_endpoint(oidc_client.validateIdp(), logger,
                           "idp_url is not equal to the issuer in .well-known")
    logger.info("IDP endpoint is OK")
    logger.info("Checking oxTrustAPI is enabled")
    oxtrustapi_credentials = http.to_base64_creds(client_id, client_secret)
    logger.debug("oxtrustapi_credentials: {}", oxtrustapi_credentials)
    oxtrust_api_client = OxTrustAPIClient("{}/identity/restv1/api/v1".format(idp_url), oxtrustapi_credentials,
                                          logger=logger)
    validators.validate_or_raise_for_value(oxtrust_api_client.validateAPI(), logger, "RPT token is None")
    logger.info("oxTrustAPI endpoint is OK")


def execute_in_gluu_chroot(command, logger=None):
    return os_cmd.execute_in_bash(
        "ssh -o IdentityFile=/etc/gluu/keys/gluu-console -o Port=60022 -o LogLevel=QUIET -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=yes root@localhost " + "\"" + command + "\"",
        logger)


def get_salt_from_chroot():
    f = open("/opt/gluu-server/etc/gluu/conf/salt")
    salt = f.read()
    f.close()
    return salt.split("=")[1].strip()


def get_salt_from_eks(logger):
    oxauth_pod = os_cmd.execute_in_bash(
        "kubectl --namespace=gluu get pods | grep oxauth | grep Running | grep -m1 ^ | awk '{print $1}'").decode().rstrip(
        "\n\r")
    logger.debug("oxauth_pod: '{}'.".format(oxauth_pod))
    salt_line = os_cmd.execute_in_bash("kubectl --namespace=gluu exec {} -- cat /etc/gluu/conf/salt".format(oxauth_pod)).decode()
    logger.debug("salt_line: '{}'.".format(salt_line))
    salt = salt_line.split("=")[1].strip()
    logger.debug("salt: '{}'.".format(salt))
    return salt


def encode_with_gluu_salt(data, salt):
    """
    Encode a string or bytes with Gluu salt using Triple DES and return Base64.
    
    :param data: string or bytes to be encoded
    :param salt: salt value (must be 16 or 24 bytes for Triple DES)
    :return: Base64-encoded encrypted string
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        raise TypeError("data must be of type str or bytes")

    engine = triple_des(salt, ECB, pad=None, padmode=PAD_PKCS5)
    encrypted = engine.encrypt(data_bytes)
    return base64.b64encode(encrypted).decode()


def decode_with_gluu_salt(data, salt):
    cipher = triple_des(salt)
    decrypted = cipher.decrypt(base64.b64decode(data), padmode=PAD_PKCS5)
    return decrypted


def gluu_decode(salt_file, data):
    f = open(salt_file)
    salt_property = f.read()
    f.close()
    key = salt_property.split("=")[1].strip()
    return decode_with_gluu_salt(data, key)


def gluu_encode(salt_file, data):
    f = open(salt_file)
    salt_property = f.read()
    f.close()
    key = salt_property.split("=")[1].strip()
    engine = triple_des(key, ECB, pad=None, padmode=PAD_PKCS5)
    en_data = engine.encrypt(data.encode('ascii'))
    b64_data = base64.b64encode(en_data).decode()
    return b64_data


def get_documents_from_ldif(ldif_file, logger):
    gluu4json = Gluu4JSON(logger)
    return gluu4json.get_documents_from_ldif(ldif_file)
