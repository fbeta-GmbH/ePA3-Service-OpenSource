import json

from app.runtime_config.logging import logger
from app.app.client import _init_and_authenticate


def retrieve_document_from_epa(insurant_id: str, document_unique_id: str, repository_unique_id: str = ""):
        vau_con, vau_np, AS_URL = _init_and_authenticate(insurant_id)

        logger.info("--------------RETRIEVE DOCUMENT START------------------")
        if vau_np:
            response = vau_con.retrieve_document(
                vau_np=vau_np,
                document_unique_id=document_unique_id,
                insurant_id=insurant_id,
                repository_unique_id=repository_unique_id,
            )
            # RetrieveDocumentSetResponse wraps RegistryResponse as a child element
            registry_response = response['body'].get('RegistryResponse', {})
            retrieve_status = registry_response.get('status', response['body'].get('status'))
            if retrieve_status == 'urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success':
                logger.info("Document retrieved successfully")
                doc_response_list = response['body'].get('DocumentResponse', [])
                if doc_response_list:
                    logger.info("Retrieved %d document(s)", len(doc_response_list))
            else:
                reg_errors = registry_response.get('RegistryErrorList', {}).get('RegistryError', [])
                raise ValueError(f"Document retrieval failed with errors: {', '.join([f"{e['errorCode']} ({e['codeContext']})" for e in reg_errors])}. Details: {json.dumps(registry_response.get('RegistryErrorList', {}), indent=4)}")

            logger.info("--------------RETRIEVE DOCUMENT ABGESCHLOSSEN------------------")
            return response


def search_documents_in_epa(insurant_id: str, status_values: list[str] | None = None,
                            creation_time_from: str | None = None, creation_time_to: str | None = None,
                            class_codes: list[str] | None = None, type_codes: list[str] | None = None,
                            format_codes: list[str] | None = None, title: str | None = None,
                            comments: str | None = None, return_type: str = "LeafClass"):
        vau_con, vau_np, AS_URL = _init_and_authenticate(insurant_id)

        logger.info("--------------SEARCH DOCUMENTS START------------------")
        if vau_np:
            response = vau_con.search_documents(
                vau_np=vau_np,
                insurant_id=insurant_id,
                status_values=status_values,
                creation_time_from=creation_time_from,
                creation_time_to=creation_time_to,
                class_codes=class_codes,
                type_codes=type_codes,
                format_codes=format_codes,
                title=title,
                comments=comments,
                return_type=return_type,
            )
            if response['body'].get('status') == 'urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success':
                registry_object_list = response['body'].get('RegistryObjectList') or {}
                extrinsic_objects = registry_object_list.get('ExtrinsicObject') or []
                logger.info(f"Search completed successfully. Found {len(extrinsic_objects)} document(s)")
            else:
                reg_errors = response['body'].get('RegistryErrorList', {}).get('RegistryError', [])
                raise ValueError(f"Document search failed with errors: {', '.join([f"{e['errorCode']} ({e['codeContext']})" for e in reg_errors])}. Details: {json.dumps(response['body'].get('RegistryErrorList', {}), indent=4)}")

            logger.info("--------------SEARCH DOCUMENTS ABGESCHLOSSEN------------------")
            return response


if __name__ == "__main__":
    logger.info("Starting ePA find client")

    INSURANT_ID = "X99999999"
    DOCUMENT_TITLE = "Testdokument"

    # Step 1: Search for documents by title
    search_response = search_documents_in_epa(
        insurant_id=INSURANT_ID,
        title=DOCUMENT_TITLE,
    )
    if not search_response:
        logger.error("Search response is empty or None")
        exit(1)

    # Step 2: Retrieve the first found document
    extrinsic_objects = (search_response['body'].get('RegistryObjectList') or {}).get('ExtrinsicObject') or []
    unique_id = next(
        (eid.get('value') for doc in extrinsic_objects
         for eid in (doc.get('ExternalIdentifier') or [])
         if eid.get('identificationScheme') == 'urn:uuid:2e82c1f6-a085-4c72-9da3-8640a32e42ab'),
        None
    )
    if unique_id:
        logger.info(f"Retrieving document with uniqueId: {unique_id}")
        retrieve_response = retrieve_document_from_epa(insurant_id=INSURANT_ID, document_unique_id=unique_id)
    else:
        logger.error("No document uniqueId found in search results")
