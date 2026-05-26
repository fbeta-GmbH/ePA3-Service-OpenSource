
import os

import json

from app.logging_config import logger

from app.vau import VAUProtokoll
from app.konnektor import Konnektor
from app.idp_handler import identitiprovider

import app.utils.utils as utils
from app.xml_service.soap_client import SoapClient


from app.utils.cert_data_util import ReadCertData
from app.constants import DEFAULT_AS_URL, set_telematik_id, set_oid_diga


def send_document_to_epa(metadata: dict, document_file_name: str):
        document_file_location = os.path.join(os.path.dirname(__file__),'..', 'data', document_file_name)
        
        logger.info("Starting ePA-Client")

        AS_URL = DEFAULT_AS_URL


        logger.info("Creating new session")
        vau_con = VAUProtokoll.VAUKanal(AS_URL)

        
        logger.info("Initializing Konnektor")
        p12_path = os.path.join(os.path.dirname(__file__),'..', 'data', 'KVS_Client_172.026.002.094.p12')
        auth = Konnektor.Konnektor(p12_path)

        logger.info("Initializing IdentitiProvider")
        idp = identitiprovider.IdentitiProvider()


        # Get nonce from VAUProtokoll
        nonce = vau_con.get_nonce(insurant_id=metadata['insurantId'])

        #Get card handle and certificate
        card, card_certificate = auth.get_card_data()

        card = auth.get_cards()
        
        is_verified = auth.is_card_pin_verified(card_handle=card)
        logger.info("Card PIN verified: %s", is_verified)

        card_certificate = auth.read_card_certificate(card_handle=card)
        auth.store_card_data(card=card, card_certificate=card_certificate)
        logger.info("Stored card data")

        set_telematik_id(ReadCertData(cert_base64=card_certificate).read_telematik_id())
        set_oid_diga(ReadCertData(cert_base64=card_certificate).read_profession_oid())


        # Create signed attest JWT
        attest_jwt = auth.create_signed_attest_jwt(nonce=nonce, card_handle=card, card_certificate=card_certificate)

        # Create challenge token
        challenge_token, user_consent = vau_con.send_authorization_request_sc(insurant_id=metadata['insurantId'])

        header_payload_challenge_string = idp.auth_build_inner_header_payload(challenge_token=challenge_token, card_cert=card_certificate)

        logger.info("Challenge token received: %s", challenge_token)
        logger.info("User consent received: %s", user_consent)

        # Verify challenge token signature
        if idp.verify_challenge_token(challenge_token):
            logger.info("Challenge token signature verified successfully")

            # Sign the challenge token
            challenge_signature = auth.get_challenge_token_signature(header_payload_challenge_string , card_handle=card)
            logger.info("Challenge token signed: %s", challenge_signature)

            # Post the signed challenge and auth certificate
            challenge_jwt = idp.auth_build_njwt(header_payload_challenge_string, challenge_signature, utils.read_keyless_jwt(challenge_token)['exp'])
            logger.info("Challenge JWT received: %s", challenge_jwt)

            # send auth code
            vau_np = vau_con.send_authcode_sc(authcode=challenge_jwt, client_attest_jwt=attest_jwt, insurant_id=metadata['insurantId'])
            logger.info("Vau NP: %s", vau_np)
            
        else:
            raise ValueError("Challenge token signature verification failed")

        logger.info("--------------AUTH ABGESCHLOSSEN------------------")
        logger.info("--------------SEND DATA START------------------")
        if vau_np:            
            # Construct the SOAP message
            document_upload_request_data, _ = SoapClient.create_upload_request(metadata)
            document_upload_message = SoapClient.build_epa_add_document_message(document_upload_request_data, AS_URL, document_path=document_file_location)

            # Use the fixed header in the upload
            response = vau_con.upload_document(
                vau_np=vau_np, 
                soap_message=document_upload_message["package"], 
                boundary_string=document_upload_message["boundary"],
                insurant_id=metadata['insurantId']
            )
            if response['body']['status'] == 'urn:oasis:names:tc:ebxml-regrep:ResponseStatusType:Success':
                logger.info("Document uploaded successfully")
            else:
                reg_errors = response['body'].get('RegistryErrorList', {}).get('RegistryError', [])
                raise ValueError(f"Document upload failed with errors: {', '.join([f"{e['errorCode']} ({e['codeContext']})" for e in reg_errors])}. Details: {json.dumps(response['body']['RegistryErrorList'], indent=4)}")

        logger.info("--------------SEND DATA ABGESCHLOSSEN------------------")


if __name__ == "__main__":
    logger.info("Starting ePA client")

    sample_metadata = {
        "insurantId": "X99999999",
        "documentEntry": {
            "creationTime": "20230609115053",
            "title": "Testdokument",
            "URI": "Testdokument.xml",
            "entryUUID": "urn:uuid:8b7a4223-ce93-49fa-9a9b-3ba2e55279ca"
            # OPTIONAL - If you want to replace a document
            # "oldEntryUUID": "DocumentEntry_old.entryUUID",
        }
    }

    send_document_to_epa(
        metadata=sample_metadata,
        document_file_name="REAL_EXAMPLE_1_KBV_PR_MIO_DIGA_Bundle.xml"
    )
