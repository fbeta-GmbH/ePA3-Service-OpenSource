from datetime import datetime
from io import BytesIO
import os
import random
import uuid

from requests import Response
import zeep
import zeep.exceptions
from zeep import Client, Settings
from zeep.helpers import serialize_object
from zeep.xsd import (Any, AnySimpleType, Type)

import argparse
import textwrap
from fastapi import status
from collections import OrderedDict
from functools import lru_cache
from typing import Any, Dict, Tuple

import jsonschema
import json
from pyjson5 import load as json5_load
from pyjson5 import loads as json5_loads
from lxml import etree
from pymtom_xop import MtomAttachment, MtomTransport
from pymtom_xop.soap_envelope import SoapEnvelope
from pymtom_xop.xop_package import XopPackage


from app.runtime_config.logging import logger

import app.utils.utils as utils
from app.xml_service.documentSetRequest_model import (
    AssociationItem, ClassificationItem, Description, Document,
    ExternalIdentifierItem, ExtrinsicObject, Include, LocalizedString, Name,
    ProvideAndRegisterDocumentSetRequest, RegistryObjectList, RegistryPackage,
    Slot, SubmitObjectsRequest, ValueList,
    dict_to_defaultdict, load_document_set_request_schema,
    load_fixed_configuration, load_ig_configuration, object_to_dict)
from app.xml_service.generated_wsdl_classes import (
    CONN_AUTHSIGNATURESERVICE_V7_4_1, CONN_CERTIFICATESERVICE_V6_0_1, CONN_CARDSERVICE,
    CONN_EVENTSERVICE, XDSDOCUMENTSERVICE, WsdlOperation, WsdlService)
from app.runtime_config.constants import DEFAULT_AS_URL, get_author, get_institution, get_author_role


class SoapClient:
    """
    SoapClient class to handle SOAP requests and responses using zeep library.
    """
    max_recursion_depth = 6
    
    # Constants
    DIR_PATH = os.path.dirname(os.path.realpath(__file__))

    class Services:
        """
        Class to hold instances of different SOAP services.
        """
        AuthSignatureService = CONN_AUTHSIGNATURESERVICE_V7_4_1()
        EventService = CONN_EVENTSERVICE()
        CertificateService = CONN_CERTIFICATESERVICE_V6_0_1()
        DocumentService = XDSDOCUMENTSERVICE()
        CardService = CONN_CARDSERVICE()

    @staticmethod
    @lru_cache
    def get_client(service_identifier: WsdlService) -> Client:
        """
        Get a cached SOAP client for the given service identifier.

        Args:
            service_identifier (WsdlService): The service identifier containing WSDL information.

        Returns:
            Client: A zeep Client instance configured with the WSDL and settings.
        """
        wsdl_path = os.path.join(SoapClient.DIR_PATH, *service_identifier.wsdl)
        logger.debug(f"Connecting to WSDL: {wsdl_path}")

        settings = Settings(
            strict=True,  
            xml_huge_tree=True, 
            raw_response=True, 
            xsd_ignore_sequence_order=True, 
            forbid_external=False, 
            forbid_entities=False
        )
        return Client(wsdl=wsdl_path, settings=settings)

    @staticmethod
    def _get_child_nodes(node: Type, client: Client, level=0, is_value_list=False):
        """
        Recursively get child nodes of a given XML schema type.

        Args:
            node (Type): The XML schema type node.
            level (int, optional): The current recursion level. Defaults to 0.

        Returns:
            list: A list of dictionaries representing the child nodes.
        """
        node_resolved = node.resolve()
        node = node_resolved
        return_list = []
        if isinstance(node, AnySimpleType) and hasattr(node, "accepted_types") and len(node.accepted_types) > 0:
            return_list.append({
                "name": node.name,
                "type": node.accepted_types[0].__name__,
                "input": []
            })
        if level >= SoapClient.max_recursion_depth:
            return return_list
        

        try: 
            valueListType = client.get_type('ns2:ValueListType')
            valueType = client.get_element('ns2:Value')
        except: 
            valueListType = None
            valueType = None
        if not is_value_list and node == valueListType:
            return_list.append({
                "name": "_value_1",
                "type": str(list[str(valueType)]),
                "input": SoapClient._get_child_nodes(node, client, level + 1, True)
            })
            return return_list

        all_child_nodes = []
        if hasattr(node, "attributes"):
            all_child_nodes.extend(node.attributes)
        if hasattr(node, "elements"):
            all_child_nodes.extend(node.elements)

        for child_name, child_obj in all_child_nodes:
            new_child = {
                "name": child_name,
                "type": str(child_obj.type),
                "input": SoapClient._get_child_nodes(child_obj.type, client, level + 1)
            } 
            return_list.append(new_child)
        return return_list


    @staticmethod
    def list_operations(selectedService: WsdlService, selectedOperation: WsdlOperation|None = None):
        """
        List available operations for a specific SOAP service type.

        Args:
            selectedService (WsdlService): The selected service to list operations for.
            selectedOperation (WsdlOperation, optional): The specific operation to list. Defaults to None.
        """
        try:
            client = SoapClient.get_client(selectedService)
        except KeyError:
            logger.error(f"Invalid service type. Please choose one of: {SoapClient.Services.__dict__.keys()}")
            return
        
        services_info = []
        for service in client.wsdl.services.values():
            service_data = {"service": service.name, "ports": []}
            for port in service.ports.values():
                port_data = {"port": port.name, "operations": []}
                operations = port.binding._operations.values()
                for operation in operations:
                    if selectedOperation and str(selectedOperation) != operation.name:
                        continue
                    operation_data = {
                        "operation": operation.name,
                        "input": [],
                        "output": []
                    }
                    if operation.input:
                        if hasattr(operation.input.body.type, 'elements'):
                            for part in operation.input.body.type.elements:
                                element_name, element_type = part
                                operation_data["input"].append({
                                    "name": element_name,
                                    "type": str(element_type),
                                    "input": SoapClient._get_child_nodes(element_type.type, client=client)
                                })
                    if operation.output:
                        for part in operation.output.body.type.elements:
                            element_name, element_type = part
                            operation_data["output"].append({
                                "name": element_name,
                                "type": str(element_type.type)
                            })
                    port_data["operations"].append(operation_data)
                service_data["ports"].append(port_data)
            services_info.append(service_data)

        def print_input(input, level=0):
            for i in input:
                print(f"{'    ' * level}- {i['name']}: {i['type']}")
                print_input(i['input'], level + 1)

        for service in services_info:
            print(f"Service: {service['service']}")
            for port in service["ports"]:
                print(f"  Port: {port['port']}")
                for operation in port["operations"]:
                    print(f"    Operation: {operation['operation']}")
                    print("      Input Parameters:")
                    print_input(operation["input"], level=2)
                    print("      Output Parameters:")
                    for output_param in operation["output"]:
                        print(f"        - {output_param['name']}: {output_param['type']}")
            print("\n")

    @staticmethod
    def list_operation(selectedOperation: WsdlOperation):
        """
        List a specific operation for a given service.

        Args:
            selectedOperation (WsdlOperation): The operation to list.
        """
        SoapClient.list_operations(selectedOperation.service, selectedOperation)

    @staticmethod
    def generate_xml(operation: WsdlOperation, params: dict, raw=False) -> str:
        """
        Generate XML for a given SOAP operation with provided parameters.

        Args:
            operation (WsdlOperation): The operation to generate XML for.
            params (dict): The parameters for the operation.

        Returns:
            str: The generated XML as a string.

        Examples:
            operation = SoapClient.Services.EventService.EventServicePort.GetCards  
            params = {  
                "Context": { 
                    "MandantId": "string",  
                    "ClientSystemId": "string",  
                    "WorkplaceId": "string"
                }  
            }  
            xml_output = SoapClient.generate_xml(operation, params)  
        """
        
        client = SoapClient.get_client(operation.service)

        try:
            logger.debug(f"Generating XML for operation '{operation}' with parameters: {params}")
            response = client.create_message(client.service, operation.name, **params)

            # Ensure the namespace mapping is correct
            namespaces = response.nsmap.copy()  # Copy the existing namespaces
            if 'ns2' not in namespaces:
                namespaces['ns2'] = "urn:oasis:names:tc:ebxml-regrep:xsd:rim:3.0"  # Add the missing namespace

            # Reorder children in Classification elements
            for classification in response.xpath("//ns2:Classification", namespaces=namespaces):
                slot_elements = classification.xpath("ns2:Slot", namespaces=namespaces)
                name_elements = classification.xpath("ns2:Name", namespaces=namespaces)

                # Remove existing children, if slot or name
                for slot in slot_elements:
                    classification.remove(slot)
                for name in name_elements:
                    classification.remove(name)

                # Add Slot elements first, then Name elements
                for slot in slot_elements:
                    classification.append(slot)
                for name in name_elements:
                    classification.append(name)

        except Exception as e:
            logger.error(f"Error occurred while generating XML for operation '{operation}': {e}")
            logger.warning("Listing available operations for reference:")
            SoapClient.list_operations(operation.service, operation)
            raise
        
        if raw:
            return response
        
        generated_xml = etree.tostring(response, pretty_print=True, xml_declaration=False, encoding='utf-8').decode()

        logger.debug(f"Generated XML for operation '{operation}': \n{generated_xml}")
        return generated_xml
    
    @staticmethod
    def parse_xml_response(response: Response, operation: WsdlOperation) -> dict:
        """
        Parse the XML response from a SOAP operation.
        Args:
            response (Response): The response object containing the XML data.
            operation (WsdlOperation): The operation for which the response is parsed.
        Returns:
            dict: The parsed response as a dictionary.
        """
        client = SoapClient.get_client(operation.service)
        # get the service params
        binding = client.wsdl.services[operation.service.name].ports[operation.port].binding
        operation = binding.get(operation.name)

        try:
            # Parse the XML response 
            logger.debug(f"Processing response for operation '{operation.name}': {response.content}")
            try:
                parsed_response = binding.process_reply(client, operation, response)
            except zeep.exceptions.TransportError as e:
                if response.status_code >= status.HTTP_400_BAD_REQUEST:
                    logger.error(f"Response status code: {response.status_code}")
                    return {"Status": {"Result": "Error", "Error": f"HTTP Error {response.status_code}"}}

            # Convert the parsed response to a dictionary
            parsed_response = serialize_object(parsed_response)
        except zeep.exceptions.Fault as e:
            logger.error(f"Zeep Fault: {e}")
            return {"Status": {"Result": "XML_FAULT", "Error": str(e)}}
        except Exception as e:
            raise ValueError(f"Error proccessing response for operation '{operation.name}' ({e})")
        
        if not parsed_response:
            raise ValueError(f"Empty response for operation '{operation.name}'")
        
        logger.debug(f"Parsed XML of '{operation.name}': {json.dumps(parsed_response, indent=4, default=str)}")
        
        if not isinstance(parsed_response, dict):
            raise ValueError(f"Unexpected response type for operation '{operation.name}': {type(parsed_response)}")
        if 'Status' not in parsed_response: parsed_response["Status"] = {}
        if 'Result' not in parsed_response["Status"]: parsed_response["Status"]["Result"] = "Ok"
        if 'Error' not in parsed_response["Status"]: parsed_response["Status"]["Error"] = None

        return parsed_response

    @staticmethod
    def create_upload_request(input_data: dict) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Create a ProvideAndRegisterDocumentSetRequest object from input data.
        https://gemspec.gematik.de/docs/gemSpec/gemSpec_DM_ePA/latest/#A_14760-20

        Args:
            input_data (dict): Input data dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the ProvideAndRegisterDocumentSetRequest object.
        """
        ig_diga_data = load_ig_configuration()
        ig_diga_data = dict(dict_to_defaultdict(ig_diga_data))

        fixed_data = load_fixed_configuration()
        fixed_data = dict(dict_to_defaultdict(fixed_data))

        # Override author role based on actor type (DiGA vs Leistungserbringer)
        fixed_data["submissionSet"]["author"]["role"] = get_author_role()

        # Validate user input using the 'user' schema
        user_input_schema = load_document_set_request_schema('user')
        jsonschema.validate(input_data, user_input_schema)

        # 
        default_input = {
            "author": {
                "person": get_author(),
                "institution": get_institution()
            },
            "patientId": f"{input_data['insurantId']}^^^&1.2.276.0.76.4.8&ISO",
            "submissionSet": {
                "entryUUID": 'urn:uuid:' + str(uuid.uuid4()),
                "submissionTime": datetime.now().strftime('%Y%m%d%H%M%S'),
                "uniqueId": f'2.25.{random.randint(10000000, 99999999)}'
            },
            "documentEntry": {
                "uniqueId": f'2.25.{random.randint(10000000, 99999999)}',
                "languageCode": "de-DE",
                # "mimeType": "application/fhir+xml",
                # "confidentialityCode": [
                #     {
                #         "code": "N",
                #         "displayName": "normal",
                #         "codeSystem": "2.16.840.1.113883.5.25"
                #     }
                # ]
            }
        }
        
        if input_data["documentEntry"].get("mimeType") is None:
            if input_data["documentEntry"]["URI"].endswith(".xml"):
                default_input["documentEntry"]["mimeType"] = "application/fhir+xml"
            elif input_data["documentEntry"]["URI"].endswith(".pdf"):
                default_input["documentEntry"]["mimeType"] = "application/pdf"
            else:
                raise ValueError(
                    f"Unsupported file type for Document URI: {input_data['documentEntry']['URI']}. Supported types are .xml and .pdf."
                )
        
        # Merge default input with user input
        input_data = utils.deep_merge_dicts(default_input, input_data)
        input_data = dict(dict_to_defaultdict(input_data))
        logger.debug(f"Input data: {json.dumps(input_data, indent=4)}")

        for (a, b) in [("documentEntry", "entryUUID"), ("documentEntry", "oldEntryUUID")]:
            if input_data[a].get(b) is not None and not input_data[a][b].startswith("urn:uuid:"):
                input_data[a][b] = "urn:uuid:" + input_data[a][b]
        
        # Validate merged user input using the 'system' schema
        system_input_schema = load_document_set_request_schema('system')
        jsonschema.validate(input_data, system_input_schema)
        
        # Create the ProvideAndRegisterDocumentSetRequest object
        registry_package = RegistryPackage(
            id=input_data["submissionSet"]["entryUUID"],
            Slot=[Slot(name="submissionTime",ValueList=ValueList(Value=input_data["submissionSet"]["submissionTime"]))],
            Name=Name(LocalizedString=LocalizedString(value=input_data["submissionSet"]["title"])),
            Description=Description(LocalizedString=LocalizedString(value=input_data["submissionSet"]["comments"])),
            Classification=[
                ClassificationItem(
                    classifiedObject=input_data["submissionSet"]["entryUUID"],
                    id="SubmissionSet.contentTypeCode",
                    classificationScheme=fixed_data["submissionSet"]["contentTypeCode"]["classificationScheme"],
                    nodeRepresentation=input_data["submissionSet"]["contentTypeCode"]["code"],
                    Slot=[Slot(name="codingScheme",ValueList=ValueList(Value=input_data["submissionSet"]["contentTypeCode"]["codingScheme"]))],
                    Name=Name(LocalizedString=LocalizedString(lang="de-DE", value=input_data["submissionSet"]["contentTypeCode"]["displayName"]))
                ) if input_data["submissionSet"]["contentTypeCode"] else None,
                ClassificationItem(
                    id="SubmissionSet.author",
                    classifiedObject=input_data["submissionSet"]["entryUUID"],
                    classificationScheme=fixed_data["submissionSet"]["author"]["classificationScheme"],
                    Slot=[
                        Slot(name="author"+name, ValueList=ValueList(Value=item["author"][name.lower()] if 'author' in item else None))
                        for name, item in 
                        [(x, input_data) for x in ["Person", "Institution"]] +
                        [(x, input_data["submissionSet"]) for x in ["Specialty", "Telecommunication"]] +
                        [("Role", fixed_data["submissionSet"])]
                    ]
                ),
                ClassificationItem(
                    classifiedObject=input_data["submissionSet"]["entryUUID"],
                    classificationNode="urn:uuid:a54d6aa5-d40d-43f9-88c5-b4633d873bdd",
                    id="SubmissionSet.limitedMetadata"
                )
            ],
            ExternalIdentifier=[
                ExternalIdentifierItem(
                    id="SubmissionSet." + name,
                    value=item[name],
                    registryObject=input_data["submissionSet"]["entryUUID"],
                    identificationScheme=scheme[name]["identificationScheme"],
                    Name=Name(LocalizedString=LocalizedString(lang="de-DE", charset="UTF-8", value="XDSSubmissionSet." + name))
                ) for (name, scheme, item) in [
                    ("patientId", fixed_data, input_data), 
                    ("uniqueId", fixed_data['submissionSet'], input_data["submissionSet"])
                ]
            ]
        )

        # Create the DocumentEntry object
        extrinsic_object = ExtrinsicObject(
            id=input_data["documentEntry"]["entryUUID"],
            mimeType=input_data["documentEntry"]["mimeType"],
            isOpaque="false",
            Slot=[
                *[Slot(name=name, ValueList=ValueList(Value=input_data["documentEntry"][name] if name in input_data["documentEntry"] else None))
                    for name in ["creationTime", "languageCode", "URI", "serviceStartTime", "serviceStopTime", "legalAuthenticator", "sourcePatientId", "sourcePatientInfo"]
                    if name in input_data["documentEntry"]
                ],
                Slot(name="urn:ihe:iti:xds:2013:referenceIdList", ValueList=ValueList(Value=input_data["documentEntry"]["referenceIdList"])),
            ],
            Name=Name(LocalizedString=LocalizedString(lang="de-DE", charset="UTF-8", value=input_data["documentEntry"]["title"])),
            Classification=[
                *[ClassificationItem(
                    id=f"documentEntry.{name}_{index}",
                    nodeRepresentation=item[name]["code"],
                    classifiedObject=input_data["documentEntry"]["entryUUID"],
                    classificationScheme=fixed_data["documentEntry"][name]["classificationScheme"],
                    Slot=[Slot(name="codingScheme", ValueList=ValueList(Value=item[name]["codeSystem"]))],
                    Name=Name(LocalizedString=LocalizedString(lang="de-DE", charset="UTF-8", value=item[name]["displayName"]))
                ) for index, (name, item) in enumerate(
                    [(key, {key: x})
                        for key in ["confidentialityCode", "eventCodeList"] if key in input_data["documentEntry"] 
                        for x in input_data["documentEntry"][key]]
                    + [(x, ig_diga_data["documentEntry"]) for x in  ["classCode", "formatCode", "typeCode", "healthcareFacilityTypeCode", "practiceSettingCode"]]
                ) if name in item],
                ClassificationItem(
                    id="documentEntry.author",
                    classifiedObject=input_data["documentEntry"]["entryUUID"],
                    classificationScheme=fixed_data["documentEntry"]["author"]["classificationScheme"],
                    Slot=[
                        Slot(name="author"+name, ValueList=ValueList(Value=item["author"][name.lower()] if 'author' in item else None))
                        for name, item in 
                        [(x, input_data) for x in ["Person", "Institution"]] +
                        [(x, input_data["documentEntry"]) for x in ["Role", "Specialty", "Telecommunication"]]
                    ]
                )
            ],
            ExternalIdentifier=[
                ExternalIdentifierItem(
                    id="XDSDocumentEntry." + name, 
                    value=item[name],
                    identificationScheme=fixed_data["documentEntry"][name]["identificationScheme"],
                    registryObject=input_data["documentEntry"]["entryUUID"],
                    Name=Name(LocalizedString=LocalizedString(lang="de-DE", charset="UTF-8", value="XDSDocumentEntry." + name))
                ) for name, item in [
                    ("patientId", input_data),
                    ("uniqueId",  input_data["documentEntry"]),
                ]
            ],
            Description=Description(LocalizedString=[LocalizedString(value=input_data["documentEntry"]["comments"])])
        )
        
        association = [
            AssociationItem(
                associationType="urn:oasis:names:tc:ebxml-regrep:AssociationType:HasMember",
                sourceObject=input_data["submissionSet"]["entryUUID"],
                targetObject=input_data["documentEntry"]["entryUUID"],
                id="documentEntry.Association"
            )]
        
        # Add RPLC (Replace) Association if oldEntryUUID is present in user_data
        if 'oldEntryUUID' in input_data["documentEntry"]:
            association.append(
                AssociationItem(
                    associationType="urn:ihe:iti:2007:AssociationType:RPLC",
                    sourceObject=input_data["documentEntry"]["entryUUID"],
                    targetObject=input_data["documentEntry"]["oldEntryUUID"],
                    id="d072a6fc-253a-4206-8047-a6753509e9dd"
            ))

        document_set_request = ProvideAndRegisterDocumentSetRequest(
            SubmitObjectsRequest=SubmitObjectsRequest(
                RegistryObjectList=RegistryObjectList(
                    RegistryPackage=registry_package,
                    ExtrinsicObject=extrinsic_object,
                    Association=association
                )
            ),
            Document=Document(
                id=input_data["documentEntry"]["entryUUID"],
                Include=Include(href="")
            )
        )

        document_set_request_dict = object_to_dict(document_set_request)
        assert type(document_set_request_dict) == OrderedDict
        return document_set_request_dict, input_data

    @staticmethod
    def build_epa_add_document_message(request_dict: dict, AS_URL: str, document_path: str = None, document_data: bytes = None, file_name: str = None) -> dict:
        """
        Build an MtomAttachment object from a document string.

        Args:
            document (str): The document string to be attached.

        Returns:
            MtomAttachment: The MtomAttachment object.
        """
        if document_data is not None:
            mtom_attachment = MtomAttachment(file=BytesIO(document_data), file_name=file_name)
        elif document_path is not None:
            mtom_attachment = MtomAttachment(file=document_path)
        mtom_attachment.content_type = 'application/octet-stream'
        mtom_attachment.mime_headers = mtom_attachment._MtomAttachment__generate_mime_headers() # type: ignore
        request_dict["Document"]["_value_1"] = mtom_attachment.get_cid()
        soap_request = SoapClient.generate_xml(
            SoapClient.Services.DocumentService.I_Document_Management.DocumentRepository_ProvideAndRegisterDocumentSet_b, 
            request_dict,
            raw=True
        )

        mtom_transport = MtomTransport()
        mtom_transport.add_files(files=[mtom_attachment])
        soap_env = SoapEnvelope(env_el=soap_request, files=mtom_transport.files)
        soap_env.type = 'application/soap+xml; action=\\"urn:ihe:iti:2007:ProvideAndRegisterDocumentSet-b\\"'
        soap_env.content_transfer_encoding = 'binary'
        soap_env.mime_headers = soap_env._SoapEnvelope__generate_mime_headers() # type: ignore
        
        def custom_get_xop_env_as_bytes(soap_env):
            text = etree.tostring(soap_env.soap_env, pretty_print=True, xml_declaration=False, encoding='utf-8').decode('utf-8')
            text = text.replace('  ', '    ')
            return textwrap.indent(text, '    ').encode('utf-8')
        
        soap_env.get_xop_env_as_bytes = lambda: custom_get_xop_env_as_bytes(soap_env)
        
        xop_pack = XopPackage(soap_env=soap_env, files=mtom_transport.files)

        # Replace the default URL in the package with the AS_URL
        xop_pack.package = xop_pack.package.replace(b'https://FQDN-from-DNS-lookup:443', AS_URL.encode('utf-8').rstrip(b'/'))

        mtom_xop_headers = mtom_transport.generate_http_headers(
            start_cid=soap_env.get_cid(), boundary=xop_pack.boundary
        )

        mtom_attachment_info = {
            "package": xop_pack.package,
            "headers": mtom_xop_headers,
            "boundary": xop_pack.boundary.decode("utf-8")
        }
        logger.debug(f"MTOM attachment created!")
        logger.debug(f"Headers: {mtom_attachment_info['headers']}")
        logger.debug(f"Boundary: {mtom_attachment_info['boundary']}")
        return mtom_attachment_info

    @staticmethod
    def build_epa_retrieve_request_message(document_unique_id: str, repository_unique_id: str) -> str:
        """
        Build a SOAP XML message for RetrieveDocumentSet (ITI-43).

        Args:
            document_unique_id (str): The unique ID of the document to retrieve.
            repository_unique_id (str): The unique ID of the repository.

        Returns:
            str: The generated SOAP XML as a string.
        """
        params = {
            "DocumentRequest": {
                "DocumentUniqueId": document_unique_id,
                "RepositoryUniqueId": repository_unique_id,
            }
        }
        return SoapClient.generate_xml(
            SoapClient.Services.DocumentService.I_Document_Management.DocumentRepository_RetrieveDocumentSet,
            params
        )

    @staticmethod
    def build_epa_search_request_message(
        patient_id: str,
        status_values: list[str] | None = None,
        creation_time_from: str | None = None,
        creation_time_to: str | None = None,
        class_codes: list[str] | None = None,
        type_codes: list[str] | None = None,
        format_codes: list[str] | None = None,
        title: str | None = None,
        comments: str | None = None,
        return_type: str = "LeafClass",
    ) -> str:
        """
        Build a SOAP XML message for RegistryStoredQuery / FindDocuments (ITI-18).

        Uses the appropriate gematik query variant:
        - FindDocumentsByTitle (A_17198-02) when title is provided
        - FindDocumentsByComment (A_25187-01) when comments is provided
        - Standard FindDocuments otherwise

        Args:
            patient_id (str): The patient ID in format "KVNR^^^&1.2.276.0.76.4.8&ISO".
            status_values (list[str]): Document status filter values.
            creation_time_from (str): Creation time lower bound (YYYYMMDDHHmmss).
            creation_time_to (str): Creation time upper bound (YYYYMMDDHHmmss).
            class_codes (list[str]): Class code filter values.
            type_codes (list[str]): Type code filter values.
            format_codes (list[str]): Format code filter values.
            title (str): Document title filter (uses FindDocumentsByTitle query, supports SQL LIKE patterns).
            comments (str): Document comments filter (uses FindDocumentsByComment query, supports SQL LIKE patterns).
            return_type (str): "LeafClass" for full metadata or "ObjectRef" for IDs only.

        Returns:
            str: The generated SOAP XML as a string.
        """
        if status_values is None:
            status_values = ["urn:oasis:names:tc:ebxml-regrep:StatusType:Approved"]

        slots = [
            Slot(name="$XDSDocumentEntryPatientId", ValueList=ValueList(Value=[f"('{patient_id}')"])),
            Slot(name="$XDSDocumentEntryStatus", ValueList=ValueList(Value=[f"('{s}')" for s in status_values])),
        ]

        if creation_time_from:
            slots.append(Slot(name="$XDSDocumentEntryCreationTimeFrom", ValueList=ValueList(Value=creation_time_from)))
        if creation_time_to:
            slots.append(Slot(name="$XDSDocumentEntryCreationTimeTo", ValueList=ValueList(Value=creation_time_to)))
        if class_codes:
            slots.append(Slot(name="$XDSDocumentEntryClassCode", ValueList=ValueList(Value=[f"('{c}')" for c in class_codes])))
        if type_codes:
            slots.append(Slot(name="$XDSDocumentEntryTypeCode", ValueList=ValueList(Value=[f"('{t}')" for t in type_codes])))
        if format_codes:
            slots.append(Slot(name="$XDSDocumentEntryFormatCode", ValueList=ValueList(Value=[f"('{f}')" for f in format_codes])))

        # Determine query ID based on search type (gematik-specific extensions)
        if comments:
            query_id = "urn:uuid:2609dda5-2b97-44d5-a795-3e999c24ca99"  # FindDocumentsByComment (A_25187-01)
            slots.append(Slot(name="$XDSDocumentEntryComments", ValueList=ValueList(Value=f"('{comments}')")))
        elif title:
            query_id = "urn:uuid:ab474085-82b5-402d-8115-3f37cb1e2405"  # FindDocumentsByTitle (A_17198-02)
            slots.append(Slot(name="$XDSDocumentEntryTitle", ValueList=ValueList(Value=f"('{title}')")))
        else:
            query_id = "urn:uuid:14d4debf-8f97-4251-9a74-a90016b0af0d"  # FindDocuments

        params = {
            "AdhocQuery": {
                "id": query_id,
                "Slot": object_to_dict(slots),
            },
            "ResponseOption": {
                "returnType": return_type,
            },
        }
        return SoapClient.generate_xml(
            SoapClient.Services.DocumentService.I_Document_Management.DocumentRegistry_RegistryStoredQuery,
            params
        )



def main():
    """
    Main function to demonstrate the usage of SoapClient.
    """
    operation = SoapClient.Services.EventService.EventServicePort.GetCards
    params = {
        "Context": {
            "MandantId": "string",
            "ClientSystemId": "string",
            "WorkplaceId": "string"
        }
    }
    
    xml_output = SoapClient.generate_xml(operation, params)

    SoapClient.list_operations(SoapClient.Services.CertificateService, SoapClient.Services.CertificateService.CertificateServicePort.
    ReadCardCertificate)

    logger.info(xml_output)
    soap_request = SoapClient.generate_xml(
        SoapClient.Services.AuthSignatureService.AuthSignatureServicePort.ExternalAuthenticate,
        params={
            "CardHandle": 'string',
            "Context": {
                "MandantId": "Test",
                "ClientSystemId": "Test_Clientsystem",
                "WorkplaceId": "Test-Arbeitsplatz"
            },
            "OptionalInputs": {
                "SignatureType": 'string',
                "SignatureSchemes": "RSASSA-PSS" if 'string' == "urn:ietf:rfc:3447" else None
            },
            "BinaryString": {
                "Base64Data": {
                    "_value_1": 'string',
                    "MimeType": 'string'
                }
            }
        }
    )
    
    logger.info(soap_request)
    
    SoapClient.list_operations(SoapClient.Services.AuthSignatureService, SoapClient.Services.AuthSignatureService.AuthSignatureServicePort.ExternalAuthenticate)



if __name__ == "__main__":
    """
    Main function to handle command-line input and create ProvideAndRegisterDocumentSetRequest.
    """
    main()
    AS_URL = DEFAULT_AS_URL
    parser = argparse.ArgumentParser(description="Create ProvideAndRegisterDocumentSetRequest from input data.")

    parser.add_argument("input", help="Path to the input JSON file or a JSON string representing the input dictionary.", default=os.path.join(os.path.dirname(__file__), "..", "data", "examples", "payloads", "sample_upload_user_input.json"), nargs="?")

    parser.add_argument("-d", "--document", help="Path to the document file to be included in the request.", default=os.path.join(os.path.dirname(__file__), "..", "data", "examples", "documents", "REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml"))

    parser.add_argument("-o", "--output", help="Path to the output XML file.", default=os.path.join(os.path.dirname(__file__), "provideAndRegisterDocumentSetRequest.xml"))

    args = parser.parse_args()

    if os.path.isfile(args.input):
        with open(args.input, "r", encoding="utf-8") as f:
            input_data = json5_load(f)
    else:
        input_data = json5_loads(args.input)

    if os.path.isfile(args.document):
        pass
    else:
        raise FileNotFoundError(f"Document file not found: {args.document}")
    
    document_set_request_data, _ = SoapClient.create_upload_request(input_data)

    document_set_request_message = SoapClient.build_epa_add_document_message(document_set_request_data, AS_URL, document_path=args.document, file_name=os.path.basename(args.document))
    
    with open(args.output, "bw") as f:
        f.write(document_set_request_message["package"])
        logger.info(f"ProvideAndRegisterDocumentSetRequest XML saved to: {args.output}")
    
