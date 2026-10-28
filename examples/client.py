from epa_core import bootstrap_environment

import json
from pathlib import Path

import requests
from epa_core.konnektor.pkcs12adapter import find_p12

from epa_core.vau import InnerHttpRequest, VAUProtokoll
from epa_core.konnektor import Konnektor
from epa_core.idp_handler import identityprovider

import epa_core.utils.utils as utils
import epa_core.vau.utils as vau_utils
from epa_core.xml_service.soap_client import SoapClient

from epa_core.utils.cert_data_util import ReadCertData
from epa_core.runtime_config.constants import Config, set_telematik_id, set_cert_author_fields

bootstrap_environment(Path("config"))

def _init_and_authenticate(insurant_id: str):
        """Initialize Konnektor, IDP and VAU session, authenticate and return (vau_con, vau_np)."""
        Config.logger.info("Starting ePA-Client")

        AS_URL = Config.DEFAULT_AS_URL

        Config.logger.info("Creating new session")
        vau_con = VAUProtokoll.VAUKanal(AS_URL)

        Config.logger.info("Initializing Konnektor")
        p12_path = find_p12(str(Path("config")))
        auth = Konnektor.Konnektor(p12_path)

        Config.logger.info("Initializing IdentityProvider")
        idp = identityprovider.IdentityProvider()


        # Get nonce from VAUProtokoll
        nonce = vau_con.get_nonce(insurant_id=insurant_id)

        #Get card handle and certificate
        card, card_certificate = auth.get_card_data()

        card = auth.get_cards()

        is_verified = auth.is_card_pin_verified(card_handle=card)
        Config.logger.info("Card PIN verified: %s", is_verified)

        card_certificate = auth.read_card_certificate(card_handle=card)
        auth.store_card_data(card=card, card_certificate=card_certificate)
        Config.logger.info("Stored card data")

        cert_data = ReadCertData(cert_base64=card_certificate)
        set_telematik_id(cert_data.read_telematik_id())
        set_cert_author_fields(cert_data)


        # Create signed attest JWT
        attest_jwt = auth.create_signed_attest_jwt(nonce=nonce, card_handle=card, card_certificate=card_certificate)

        # Create challenge token
        challenge_token, user_consent = vau_con.send_authorization_request_sc(insurant_id=insurant_id)

        header_payload_challenge_string = idp.auth_build_inner_header_payload(challenge_token=challenge_token, card_cert=card_certificate)

        Config.logger.info("Challenge token received: %s", challenge_token)
        Config.logger.info("User consent received: %s", user_consent)

        # Verify challenge token signature
        if idp.verify_challenge_token(challenge_token):
            Config.logger.info("Challenge token signature verified successfully")

            # Sign the challenge token
            challenge_signature = auth.get_challenge_token_signature(header_payload_challenge_string , card_handle=card)
            Config.logger.info("Challenge token signed: %s", challenge_signature)

            # Post the signed challenge and auth certificate
            challenge_jwt = idp.auth_build_njwt(header_payload_challenge_string, challenge_signature, utils.read_keyless_jwt(challenge_token)['exp'])
            Config.logger.info("Challenge JWT received: %s", challenge_jwt)

            # send auth code
            vau_np = vau_con.send_authcode_sc(authcode=challenge_jwt, client_attest_jwt=attest_jwt, insurant_id=insurant_id)
            Config.logger.info("Vau NP: %s", vau_np)

        else:
            raise ValueError("Challenge token signature verification failed")

        Config.logger.info("--------------AUTH ABGESCHLOSSEN------------------")
        return vau_con, vau_np, AS_URL


def send_document_to_epa(metadata: dict, document_file_name: str):
        document_file_location = str(Config.DATA_DIR / 'examples' / 'documents' / document_file_name)

        vau_con, vau_np, AS_URL = _init_and_authenticate(metadata['insurantId'])

        Config.logger.info("--------------SEND DATA START------------------")
        if vau_np:
            # Construct the SOAP message
            document_upload_request_data, _ = SoapClient.create_upload_request(metadata)
            document_upload_message = SoapClient.build_epa_add_document_message(document_upload_request_data, AS_URL, document_path=document_file_location)

            content_type = (
                'multipart/related;start-info="application/soap+xml";'
                'type="application/xop+xml";'
                'action="urn:ihe:iti:2007:ProvideAndRegisterDocumentSet-b";'
                f'boundary={document_upload_message["boundary"]}'
            )
            inner = vau_con.execute(
                InnerHttpRequest(
                    method="POST",
                    path="/epa/xds-document/api/I_Document_Management",
                    insurant_id=metadata["insurantId"],
                    headers={"Content-Type": content_type},
                    body=document_upload_message["package"],
                ),
                vau_np=vau_np,
            )
            response_obj = requests.Response()
            if isinstance(inner.body, bytes):
                response_obj._content = inner.body
            elif isinstance(inner.body, str):
                response_obj._content = inner.body.encode("utf-8")
            else:
                response_obj._content = json.dumps(inner.body).encode("utf-8")
            response_obj.status_code = inner.status_code
            response_obj.encoding = "utf-8"
            response_obj.headers = dict(inner.headers)
            response_body = SoapClient.parse_xml_response(
                response_obj,
                SoapClient.Services.DocumentService.I_Document_Management.DocumentRepository_ProvideAndRegisterDocumentSet_b,
            )
            vau_utils.check_upload_response_for_errors(response_body)
            if response_body['status'] == 'urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success':
                Config.logger.info("Document uploaded successfully")
            else:
                reg_errors = response_body.get('RegistryErrorList', {}).get('RegistryError', [])
                raise ValueError(f"Document upload failed with errors: {', '.join([f"{e['errorCode']} ({e['codeContext']})" for e in reg_errors])}. Details: {json.dumps(response_body['RegistryErrorList'], indent=4)}")

        Config.logger.info("--------------SEND DATA ABGESCHLOSSEN------------------")


if __name__ == "__main__":
    Config.logger.info("Starting ePA client")

    INSURANT_ID = "X110596703"
    DOCUMENT_TITLE = "Testdokument"

    sample_metadata = {
        "insurantId": INSURANT_ID,
        "documentEntry": {
            "creationTime": "20260616115053",
            "title": DOCUMENT_TITLE,
            "URI": f"{DOCUMENT_TITLE}.xml",
            "entryUUID": "urn:uuid:8b7a4223-ce93-49fa-9a9b-3ba2e55279ca"
            # OPTIONAL - If you want to replace a document
            # "oldEntryUUID": "DocumentEntry_old.entryUUID",
        }
    }

    send_document_to_epa(
        metadata=sample_metadata,
        document_file_name="REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml"
    )
