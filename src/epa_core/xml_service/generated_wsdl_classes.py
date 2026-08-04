class WsdlService:
    def __init__(self, name='', wsdl=[]):
        self.name: str = name
        self.wsdl: list[str] = wsdl
    def __str__(self): return self.name

class WsdlOperation:
    def __init__(self, name, port, service, wsdl):
        self.name: str = name
        self.port: str = port
        self.service = WsdlService(service, wsdl)
    def __str__(self): return self.name


class CM_CC_CCS(WsdlService):
    def __init__(self):
        super().__init__('CCService', ['schemas', 'cm', 'cc', 'CCS.wsdl'])
    class _CCSPort:
        def __str__(self): return 'CCSPort'
        PerformUpdates = WsdlOperation('PerformUpdates', 'CCSPort', 'CCService', ['schemas', 'cm', 'cc', 'CCS.wsdl'])
        GetNextCommandPackage = WsdlOperation('GetNextCommandPackage', 'CCSPort', 'CCService', ['schemas', 'cm', 'cc', 'CCS.wsdl'])
    CCSPort = _CCSPort()



class CM_UF_UFS(WsdlService):
    def __init__(self):
        super().__init__('UFService', ['schemas', 'cm', 'uf', 'UFS.wsdl'])
    class _UFSPort:
        def __str__(self): return 'UFSPort'
        GetUpdateFlags = WsdlOperation('GetUpdateFlags', 'UFSPort', 'UFService', ['schemas', 'cm', 'uf', 'UFS.wsdl'])
    UFSPort = _UFSPort()



class CONN_AUTHSIGNATURESERVICE(WsdlService):
    def __init__(self):
        super().__init__('AuthSignatureService', ['schemas', 'conn', 'AuthSignatureService.wsdl'])
    class _AuthSignatureServicePort:
        def __str__(self): return 'AuthSignatureServicePort'
        ExternalAuthenticate = WsdlOperation('ExternalAuthenticate', 'AuthSignatureServicePort', 'AuthSignatureService', ['schemas', 'conn', 'AuthSignatureService.wsdl'])
    AuthSignatureServicePort = _AuthSignatureServicePort()



class CONN_AUTHSIGNATURESERVICE_V7_4_1(WsdlService):
    def __init__(self):
        super().__init__('AuthSignatureService', ['schemas', 'conn', 'AuthSignatureService_v7_4_1.wsdl'])
    class _AuthSignatureServicePort:
        def __str__(self): return 'AuthSignatureServicePort'
        ExternalAuthenticate = WsdlOperation('ExternalAuthenticate', 'AuthSignatureServicePort', 'AuthSignatureService', ['schemas', 'conn', 'AuthSignatureService_v7_4_1.wsdl'])
    AuthSignatureServicePort = _AuthSignatureServicePort()



class CONN_CARDSERVICE(WsdlService):
    def __init__(self):
        super().__init__('CardService', ['schemas', 'conn', 'CardService.wsdl'])
    class _CardServicePort:
        def __str__(self): return 'CardServicePort'
        VerifyPin = WsdlOperation('VerifyPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService.wsdl'])
        ChangePin = WsdlOperation('ChangePin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService.wsdl'])
        UnblockPin = WsdlOperation('UnblockPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService.wsdl'])
        GetPinStatus = WsdlOperation('GetPinStatus', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService.wsdl'])
        AuthorizeSMC = WsdlOperation('AuthorizeSMC', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService.wsdl'])
    CardServicePort = _CardServicePort()



class CONN_CARDSERVICE_V8_1_1(WsdlService):
    def __init__(self):
        super().__init__('CardService', ['schemas', 'conn', 'CardService_v8_1_1.wsdl'])
    class _CardServicePort:
        def __str__(self): return 'CardServicePort'
        VerifyPin = WsdlOperation('VerifyPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_1.wsdl'])
        ChangePin = WsdlOperation('ChangePin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_1.wsdl'])
        UnblockPin = WsdlOperation('UnblockPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_1.wsdl'])
        GetPinStatus = WsdlOperation('GetPinStatus', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_1.wsdl'])
    CardServicePort = _CardServicePort()



class CONN_CARDSERVICE_V8_1_2(WsdlService):
    def __init__(self):
        super().__init__('CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
    class _CardServicePort:
        def __str__(self): return 'CardServicePort'
        VerifyPin = WsdlOperation('VerifyPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
        ChangePin = WsdlOperation('ChangePin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
        UnblockPin = WsdlOperation('UnblockPin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
        GetPinStatus = WsdlOperation('GetPinStatus', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
        EnablePin = WsdlOperation('EnablePin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
        DisablePin = WsdlOperation('DisablePin', 'CardServicePort', 'CardService', ['schemas', 'conn', 'CardService_v8_1_2.wsdl'])
    CardServicePort = _CardServicePort()



class CONN_CARDTERMINALSERVICE(WsdlService):
    def __init__(self):
        super().__init__('CardTerminalService', ['schemas', 'conn', 'CardTerminalService.wsdl'])
    class _CardTerminalServicePort:
        def __str__(self): return 'CardTerminalServicePort'
        RequestCard = WsdlOperation('RequestCard', 'CardTerminalServicePort', 'CardTerminalService', ['schemas', 'conn', 'CardTerminalService.wsdl'])
        EjectCard = WsdlOperation('EjectCard', 'CardTerminalServicePort', 'CardTerminalService', ['schemas', 'conn', 'CardTerminalService.wsdl'])
    CardTerminalServicePort = _CardTerminalServicePort()



class CONN_CERTIFICATESERVICE(WsdlService):
    def __init__(self):
        super().__init__('CertificateService', ['schemas', 'conn', 'CertificateService.wsdl'])
    class _CertificateServicePort:
        def __str__(self): return 'CertificateServicePort'
        CheckCertificateExpiration = WsdlOperation('CheckCertificateExpiration', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService.wsdl'])
        ReadCardCertificate = WsdlOperation('ReadCardCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService.wsdl'])
        VerifyCertificate = WsdlOperation('VerifyCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService.wsdl'])
    CertificateServicePort = _CertificateServicePort()



class CONN_CERTIFICATESERVICE_V6_0_1(WsdlService):
    def __init__(self):
        super().__init__('CertificateService', ['schemas', 'conn', 'CertificateService_v6_0_1.wsdl'])
    class _CertificateServicePort:
        def __str__(self): return 'CertificateServicePort'
        CheckCertificateExpiration = WsdlOperation('CheckCertificateExpiration', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService_v6_0_1.wsdl'])
        ReadCardCertificate = WsdlOperation('ReadCardCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService_v6_0_1.wsdl'])
        VerifyCertificate = WsdlOperation('VerifyCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'conn', 'CertificateService_v6_0_1.wsdl'])
    CertificateServicePort = _CertificateServicePort()



class CONN_ENCRYPTIONSERVICE(WsdlService):
    def __init__(self):
        super().__init__('EncryptionService', ['schemas', 'conn', 'EncryptionService.wsdl'])
    class _EncryptionServicePort:
        def __str__(self): return 'EncryptionServicePort'
        EncryptDocument = WsdlOperation('EncryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'conn', 'EncryptionService.wsdl'])
        DecryptDocument = WsdlOperation('DecryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'conn', 'EncryptionService.wsdl'])
    EncryptionServicePort = _EncryptionServicePort()



class CONN_ENCRYPTIONSERVICE_V6_1_1(WsdlService):
    def __init__(self):
        super().__init__('EncryptionService', ['schemas', 'conn', 'EncryptionService_v6_1_1.wsdl'])
    class _EncryptionServicePort:
        def __str__(self): return 'EncryptionServicePort'
        EncryptDocument = WsdlOperation('EncryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'conn', 'EncryptionService_v6_1_1.wsdl'])
        DecryptDocument = WsdlOperation('DecryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'conn', 'EncryptionService_v6_1_1.wsdl'])
    EncryptionServicePort = _EncryptionServicePort()



class CONN_EVENTSERVICE(WsdlService):
    def __init__(self):
        super().__init__('EventService', ['schemas', 'conn', 'EventService.wsdl'])
    class _EventServicePort:
        def __str__(self): return 'EventServicePort'
        Subscribe = WsdlOperation('Subscribe', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        Unsubscribe = WsdlOperation('Unsubscribe', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        GetSubscription = WsdlOperation('GetSubscription', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        GetResourceInformation = WsdlOperation('GetResourceInformation', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        GetCardTerminals = WsdlOperation('GetCardTerminals', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        GetCards = WsdlOperation('GetCards', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
        RenewSubscriptions = WsdlOperation('RenewSubscriptions', 'EventServicePort', 'EventService', ['schemas', 'conn', 'EventService.wsdl'])
    EventServicePort = _EventServicePort()



class CONN_SIGNATURESERVICE_V7_4_3(WsdlService):
    def __init__(self):
        super().__init__('SignatureService', ['schemas', 'conn', 'SignatureService_V7_4_3.wsdl'])
    class _SignatureServicePort:
        def __str__(self): return 'SignatureServicePort'
        VerifyDocument = WsdlOperation('VerifyDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_4_3.wsdl'])
        SignDocument = WsdlOperation('SignDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_4_3.wsdl'])
        GetJobNumber = WsdlOperation('GetJobNumber', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_4_3.wsdl'])
        StopSignature = WsdlOperation('StopSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_4_3.wsdl'])
    SignatureServicePort = _SignatureServicePort()



class CONN_SIGNATURESERVICE_V7_5_6(WsdlService):
    def __init__(self):
        super().__init__('SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
    class _SignatureServicePort:
        def __str__(self): return 'SignatureServicePort'
        VerifyDocument = WsdlOperation('VerifyDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        SignDocument = WsdlOperation('SignDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        GetJobNumber = WsdlOperation('GetJobNumber', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        StopSignature = WsdlOperation('StopSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        ActivateComfortSignature = WsdlOperation('ActivateComfortSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        DeactivateComfortSignature = WsdlOperation('DeactivateComfortSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
        GetSignatureMode = WsdlOperation('GetSignatureMode', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_6.wsdl'])
    SignatureServicePort = _SignatureServicePort()



class CONN_SIGNATURESERVICE_V7_5_7(WsdlService):
    def __init__(self):
        super().__init__('SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
    class _SignatureServicePort:
        def __str__(self): return 'SignatureServicePort'
        VerifyDocument = WsdlOperation('VerifyDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        SignDocument = WsdlOperation('SignDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        GetJobNumber = WsdlOperation('GetJobNumber', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        StopSignature = WsdlOperation('StopSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        ActivateComfortSignature = WsdlOperation('ActivateComfortSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        DeactivateComfortSignature = WsdlOperation('DeactivateComfortSignature', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
        GetSignatureMode = WsdlOperation('GetSignatureMode', 'SignatureServicePort', 'SignatureService', ['schemas', 'conn', 'SignatureService_V7_5_7.wsdl'])
    SignatureServicePort = _SignatureServicePort()



class CONN_AMTSS_AMTSSERVICE(WsdlService):
    def __init__(self):
        super().__init__('AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
    class _AMTSServicePort:
        def __str__(self): return 'AMTSServicePort'
        ReadMP = WsdlOperation('ReadMP', 'AMTSServicePort', 'AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
        WriteMP = WsdlOperation('WriteMP', 'AMTSServicePort', 'AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
        ReadConsent = WsdlOperation('ReadConsent', 'AMTSServicePort', 'AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
        WriteConsent = WsdlOperation('WriteConsent', 'AMTSServicePort', 'AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
        DeleteConsent = WsdlOperation('DeleteConsent', 'AMTSServicePort', 'AMTSService', ['schemas', 'conn', 'amtss', 'AMTSService.wsdl'])
    AMTSServicePort = _AMTSServicePort()



class CONN_NFDS_DPESERVICE(WsdlService):
    def __init__(self):
        super().__init__('DPEService', ['schemas', 'conn', 'nfds', 'DPEService.wsdl'])
    class _DPEServicePort:
        def __str__(self): return 'DPEServicePort'
        ReadDPE = WsdlOperation('ReadDPE', 'DPEServicePort', 'DPEService', ['schemas', 'conn', 'nfds', 'DPEService.wsdl'])
        WriteDPE = WsdlOperation('WriteDPE', 'DPEServicePort', 'DPEService', ['schemas', 'conn', 'nfds', 'DPEService.wsdl'])
        EraseDPE = WsdlOperation('EraseDPE', 'DPEServicePort', 'DPEService', ['schemas', 'conn', 'nfds', 'DPEService.wsdl'])
    DPEServicePort = _DPEServicePort()



class CONN_NFDS_NFDSERVICE(WsdlService):
    def __init__(self):
        super().__init__('NFDService', ['schemas', 'conn', 'nfds', 'NFDService.wsdl'])
    class _NFDServicePort:
        def __str__(self): return 'NFDServicePort'
        ReadNFD = WsdlOperation('ReadNFD', 'NFDServicePort', 'NFDService', ['schemas', 'conn', 'nfds', 'NFDService.wsdl'])
        WriteNFD = WsdlOperation('WriteNFD', 'NFDServicePort', 'NFDService', ['schemas', 'conn', 'nfds', 'NFDService.wsdl'])
        EraseNFD = WsdlOperation('EraseNFD', 'NFDServicePort', 'NFDService', ['schemas', 'conn', 'nfds', 'NFDService.wsdl'])
    NFDServicePort = _NFDServicePort()



class CONN_PHRS_PHRMANAGEMENTSERVICE(WsdlService):
    def __init__(self):
        super().__init__('PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService.wsdl'])
    class _PHRManagementServicePort:
        def __str__(self): return 'PHRManagementServicePort'
        ActivateAccount = WsdlOperation('ActivateAccount', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService.wsdl'])
        RequestFacilityAuthorization = WsdlOperation('RequestFacilityAuthorization', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService.wsdl'])
        GetHomeCommunityID = WsdlOperation('GetHomeCommunityID', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService.wsdl'])
        GetAuthorizationList = WsdlOperation('GetAuthorizationList', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService.wsdl'])
    PHRManagementServicePort = _PHRManagementServicePort()



class CONN_PHRS_PHRMANAGEMENTSERVICE_V2_0_1(WsdlService):
    def __init__(self):
        super().__init__('PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
    class _PHRManagementServicePort:
        def __str__(self): return 'PHRManagementServicePort'
        ActivateAccount = WsdlOperation('ActivateAccount', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
        RequestFacilityAuthorization = WsdlOperation('RequestFacilityAuthorization', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
        GetHomeCommunityID = WsdlOperation('GetHomeCommunityID', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
        GetAuthorizationList = WsdlOperation('GetAuthorizationList', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
        GetAuthorizationState = WsdlOperation('GetAuthorizationState', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_1.wsdl'])
    PHRManagementServicePort = _PHRManagementServicePort()



class CONN_PHRS_PHRMANAGEMENTSERVICE_V2_0_2(WsdlService):
    def __init__(self):
        super().__init__('PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
    class _PHRManagementServicePort:
        def __str__(self): return 'PHRManagementServicePort'
        ActivateAccount = WsdlOperation('ActivateAccount', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
        RequestFacilityAuthorization = WsdlOperation('RequestFacilityAuthorization', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
        GetHomeCommunityID = WsdlOperation('GetHomeCommunityID', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
        GetAuthorizationList = WsdlOperation('GetAuthorizationList', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
        GetAuthorizationState = WsdlOperation('GetAuthorizationState', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_0_2.wsdl'])
    PHRManagementServicePort = _PHRManagementServicePort()



class CONN_PHRS_PHRMANAGEMENTSERVICE_V2_5_2(WsdlService):
    def __init__(self):
        super().__init__('PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
    class _PHRManagementServicePort:
        def __str__(self): return 'PHRManagementServicePort'
        ActivateAccount = WsdlOperation('ActivateAccount', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
        RequestFacilityAuthorization = WsdlOperation('RequestFacilityAuthorization', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
        GetHomeCommunityID = WsdlOperation('GetHomeCommunityID', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
        GetAuthorizationList = WsdlOperation('GetAuthorizationList', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
        GetAuthorizationState = WsdlOperation('GetAuthorizationState', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_2.wsdl'])
    PHRManagementServicePort = _PHRManagementServicePort()



class CONN_PHRS_PHRMANAGEMENTSERVICE_V2_5_3(WsdlService):
    def __init__(self):
        super().__init__('PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
    class _PHRManagementServicePort:
        def __str__(self): return 'PHRManagementServicePort'
        ActivateAccount = WsdlOperation('ActivateAccount', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
        RequestFacilityAuthorization = WsdlOperation('RequestFacilityAuthorization', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
        GetHomeCommunityID = WsdlOperation('GetHomeCommunityID', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
        GetAuthorizationList = WsdlOperation('GetAuthorizationList', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
        GetAuthorizationState = WsdlOperation('GetAuthorizationState', 'PHRManagementServicePort', 'PHRManagementService', ['schemas', 'conn', 'phrs', 'PHRManagementService_V2_5_3.wsdl'])
    PHRManagementServicePort = _PHRManagementServicePort()



class CONN_PHRS_PHRSERVICE(WsdlService):
    def __init__(self):
        super().__init__('PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
    class _PHRService_Port_Soap12:
        def __str__(self): return 'PHRService_Port_Soap12'
        DocumentRegistry_RegistryStoredQuery = WsdlOperation('DocumentRegistry_RegistryStoredQuery', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
        DocumentRepository_ProvideAndRegisterDocumentSet_b = WsdlOperation('DocumentRepository_ProvideAndRegisterDocumentSet-b', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
        DocumentRepository_RetrieveDocumentSet = WsdlOperation('DocumentRepository_RetrieveDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
        DocumentRepository_RemoveDocuments = WsdlOperation('DocumentRepository_RemoveDocuments', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
        UpdateResponder_RestrictedUpdateDocumentSet = WsdlOperation('UpdateResponder_RestrictedUpdateDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService.wsdl'])
    PHRService_Port_Soap12 = _PHRService_Port_Soap12()



class CONN_PHRS_PHRSERVICE_V2_0_1(WsdlService):
    def __init__(self):
        super().__init__('PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_1.wsdl'])
    class _PHRService_Port_Soap12:
        def __str__(self): return 'PHRService_Port_Soap12'
        DocumentRegistry_RegistryStoredQuery = WsdlOperation('DocumentRegistry_RegistryStoredQuery', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_1.wsdl'])
        DocumentRepository_ProvideAndRegisterDocumentSet_b = WsdlOperation('DocumentRepository_ProvideAndRegisterDocumentSet-b', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_1.wsdl'])
        DocumentRepository_RetrieveDocumentSet = WsdlOperation('DocumentRepository_RetrieveDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_1.wsdl'])
        DocumentRegistry_DeleteDocumentSet = WsdlOperation('DocumentRegistry_DeleteDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_1.wsdl'])
    PHRService_Port_Soap12 = _PHRService_Port_Soap12()



class CONN_PHRS_PHRSERVICE_V2_0_2(WsdlService):
    def __init__(self):
        super().__init__('PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_2.wsdl'])
    class _PHRService_Port_Soap12:
        def __str__(self): return 'PHRService_Port_Soap12'
        DocumentRegistry_RegistryStoredQuery = WsdlOperation('DocumentRegistry_RegistryStoredQuery', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_2.wsdl'])
        DocumentRepository_ProvideAndRegisterDocumentSet_b = WsdlOperation('DocumentRepository_ProvideAndRegisterDocumentSet-b', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_2.wsdl'])
        DocumentRepository_RetrieveDocumentSet = WsdlOperation('DocumentRepository_RetrieveDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_2.wsdl'])
        DocumentRegistry_DeleteDocumentSet = WsdlOperation('DocumentRegistry_DeleteDocumentSet', 'PHRService_Port_Soap12', 'PHRService', ['schemas', 'conn', 'phrs', 'PHRService_V2_0_2.wsdl'])
    PHRService_Port_Soap12 = _PHRService_Port_Soap12()



class CONN_TBAUTH_IDPSERVICEACTIVEREQUESTOR(WsdlService):
    def __init__(self):
        super().__init__('IdpServiceActiveRequestor', ['schemas', 'conn', 'tbauth', 'IdpServiceActiveRequestor.wsdl'])
    class _Transport_Port:
        def __str__(self): return 'Transport_Port'
        Issue = WsdlOperation('Issue', 'Transport_Port', 'IdpServiceActiveRequestor', ['schemas', 'conn', 'tbauth', 'IdpServiceActiveRequestor.wsdl'])
        Cancel = WsdlOperation('Cancel', 'Transport_Port', 'IdpServiceActiveRequestor', ['schemas', 'conn', 'tbauth', 'IdpServiceActiveRequestor.wsdl'])
        Renew = WsdlOperation('Renew', 'Transport_Port', 'IdpServiceActiveRequestor', ['schemas', 'conn', 'tbauth', 'IdpServiceActiveRequestor.wsdl'])
    Transport_Port = _Transport_Port()



class CONN_TBAUTH_LOCALIDPSERVICE(WsdlService):
    def __init__(self):
        super().__init__('LocalIdpService', ['schemas', 'conn', 'tbauth', 'LocalIdpService.wsdl'])
    class _Transport_Port:
        def __str__(self): return 'Transport_Port'
        Issue = WsdlOperation('Issue', 'Transport_Port', 'LocalIdpService', ['schemas', 'conn', 'tbauth', 'LocalIdpService.wsdl'])
    Transport_Port = _Transport_Port()



class CONN_VSDS_KVKSERVICE(WsdlService):
    def __init__(self):
        super().__init__('KVKService', ['schemas', 'conn', 'vsds', 'KvkService.wsdl'])
    class _KVKServicePort:
        def __str__(self): return 'KVKServicePort'
        ReadKVK = WsdlOperation('ReadKVK', 'KVKServicePort', 'KVKService', ['schemas', 'conn', 'vsds', 'KvkService.wsdl'])
    KVKServicePort = _KVKServicePort()



class CONN_VSDS_VSDSERVICE(WsdlService):
    def __init__(self):
        super().__init__('VSDService', ['schemas', 'conn', 'vsds', 'VSDService.wsdl'])
    class _VSDServicePort:
        def __str__(self): return 'VSDServicePort'
        ReadVSD = WsdlOperation('ReadVSD', 'VSDServicePort', 'VSDService', ['schemas', 'conn', 'vsds', 'VSDService.wsdl'])
    VSDServicePort = _VSDServicePort()



class CONSUMER_CERTIFICATESERVICE(WsdlService):
    def __init__(self):
        super().__init__('CertificateService', ['schemas', 'consumer', 'CertificateService.wsdl'])
    class _CertificateServicePort:
        def __str__(self): return 'CertificateServicePort'
        ReadCertificate = WsdlOperation('ReadCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'consumer', 'CertificateService.wsdl'])
        VerifyCertificate = WsdlOperation('VerifyCertificate', 'CertificateServicePort', 'CertificateService', ['schemas', 'consumer', 'CertificateService.wsdl'])
    CertificateServicePort = _CertificateServicePort()



class CONSUMER_ENCRYPTIONSERVICE(WsdlService):
    def __init__(self):
        super().__init__('EncryptionService', ['schemas', 'consumer', 'EncryptionService.wsdl'])
    class _EncryptionServicePort:
        def __str__(self): return 'EncryptionServicePort'
        EncryptDocument = WsdlOperation('EncryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'consumer', 'EncryptionService.wsdl'])
        DecryptDocument = WsdlOperation('DecryptDocument', 'EncryptionServicePort', 'EncryptionService', ['schemas', 'consumer', 'EncryptionService.wsdl'])
    EncryptionServicePort = _EncryptionServicePort()



class CONSUMER_EPASERVICE(WsdlService):
    def __init__(self):
        super().__init__('EPAService', ['schemas', 'consumer', 'EPAService.wsdl'])
    class _EPAServicePort:
        def __str__(self): return 'EPAServicePort'
        Logout = WsdlOperation('Logout', 'EPAServicePort', 'EPAService', ['schemas', 'consumer', 'EPAService.wsdl'])
        PutDocuments = WsdlOperation('PutDocuments', 'EPAServicePort', 'EPAService', ['schemas', 'consumer', 'EPAService.wsdl'])
    EPAServicePort = _EPAServicePort()



class CONSUMER_SIGNATURESERVICE(WsdlService):
    def __init__(self):
        super().__init__('SignatureService', ['schemas', 'consumer', 'SignatureService.wsdl'])
    class _SignatureServicePort:
        def __str__(self): return 'SignatureServicePort'
        VerifyDocument = WsdlOperation('VerifyDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'consumer', 'SignatureService.wsdl'])
        SignDocument = WsdlOperation('SignDocument', 'SignatureServicePort', 'SignatureService', ['schemas', 'consumer', 'SignatureService.wsdl'])
        ExternalAuthenticate = WsdlOperation('ExternalAuthenticate', 'SignatureServicePort', 'SignatureService', ['schemas', 'consumer', 'SignatureService.wsdl'])
    SignatureServicePort = _SignatureServicePort()



class KSR_KONFIGURATIONSDIENST(WsdlService):
    def __init__(self):
        super().__init__('Konfigurationsdienst', ['schemas', 'ksr', 'Konfigurationsdienst.wsdl'])
    class _KonfigurationsdienstPort:
        def __str__(self): return 'KonfigurationsdienstPort'
        list_Updates = WsdlOperation('list_Updates', 'KonfigurationsdienstPort', 'Konfigurationsdienst', ['schemas', 'ksr', 'Konfigurationsdienst.wsdl'])
    KonfigurationsdienstPort = _KonfigurationsdienstPort()



class STOERUNGSAMPEL_I_MONITORING_UPDATE10(WsdlService):
    def __init__(self):
        super().__init__('I_Monitoring_Update', ['schemas', 'stoerungsampel', 'I_Monitoring_Update10.wsdl'])
    class _i_mon_update:
        def __str__(self): return 'i_mon_update'
        update = WsdlOperation('update', 'i_mon_update', 'I_Monitoring_Update', ['schemas', 'stoerungsampel', 'I_Monitoring_Update10.wsdl'])
    i_mon_update = _i_mon_update()



class VPNZUGD_PROVISIONINGSERVICE(WsdlService):
    def __init__(self):
        super().__init__('provisioningService', ['schemas', 'vpnzugd', 'ProvisioningService.wsdl'])
    class _provisioningPort:
        def __str__(self): return 'provisioningPort'
        regOperation = WsdlOperation('regOperation', 'provisioningPort', 'provisioningService', ['schemas', 'vpnzugd', 'ProvisioningService.wsdl'])
        deregOperation = WsdlOperation('deregOperation', 'provisioningPort', 'provisioningService', ['schemas', 'vpnzugd', 'ProvisioningService.wsdl'])
        statusOperation = WsdlOperation('statusOperation', 'provisioningPort', 'provisioningService', ['schemas', 'vpnzugd', 'ProvisioningService.wsdl'])
        sendDataOperation = WsdlOperation('sendDataOperation', 'provisioningPort', 'provisioningService', ['schemas', 'vpnzugd', 'ProvisioningService.wsdl'])
    provisioningPort = _provisioningPort()



class VZD_DIRECTORYAPPLICATIONMAINTENANCE(WsdlService):
    def __init__(self):
        super().__init__('DirectoryApplicationMaintenanceService', ['schemas', 'vzd', 'DirectoryApplicationMaintenance.wsdl'])
    class _directoryApplicationMaintenancePort:
        def __str__(self): return 'directoryApplicationMaintenancePort'
        add = WsdlOperation('add', 'directoryApplicationMaintenancePort', 'DirectoryApplicationMaintenanceService', ['schemas', 'vzd', 'DirectoryApplicationMaintenance.wsdl'])
        modify = WsdlOperation('modify', 'directoryApplicationMaintenancePort', 'DirectoryApplicationMaintenanceService', ['schemas', 'vzd', 'DirectoryApplicationMaintenance.wsdl'])
        delete = WsdlOperation('delete', 'directoryApplicationMaintenancePort', 'DirectoryApplicationMaintenanceService', ['schemas', 'vzd', 'DirectoryApplicationMaintenance.wsdl'])
    directoryApplicationMaintenancePort = _directoryApplicationMaintenancePort()



class VZD_DIRECTORYMAINTENANCE(WsdlService):
    def __init__(self):
        super().__init__('directoryMaintenanceService', ['schemas', 'vzd', 'DirectoryMaintenance.wsdl'])
    class _directoryMaintenancePort:
        def __str__(self): return 'directoryMaintenancePort'
        add = WsdlOperation('add', 'directoryMaintenancePort', 'directoryMaintenanceService', ['schemas', 'vzd', 'DirectoryMaintenance.wsdl'])
        read = WsdlOperation('read', 'directoryMaintenancePort', 'directoryMaintenanceService', ['schemas', 'vzd', 'DirectoryMaintenance.wsdl'])
        modify = WsdlOperation('modify', 'directoryMaintenancePort', 'directoryMaintenanceService', ['schemas', 'vzd', 'DirectoryMaintenance.wsdl'])
        delete = WsdlOperation('delete', 'directoryMaintenancePort', 'directoryMaintenanceService', ['schemas', 'vzd', 'DirectoryMaintenance.wsdl'])
    directoryMaintenancePort = _directoryMaintenancePort()



class XDSDOCUMENTSERVICE(WsdlService):
    def __init__(self):
        super().__init__('XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
    class _I_Document_Management:
        def __str__(self): return 'I_Document_Management'
        DocumentRegistry_RegistryStoredQuery = WsdlOperation('DocumentRegistry_RegistryStoredQuery', 'I_Document_Management', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRepository_ProvideAndRegisterDocumentSet_b = WsdlOperation('DocumentRepository_ProvideAndRegisterDocumentSet-b', 'I_Document_Management', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRepository_RetrieveDocumentSet = WsdlOperation('DocumentRepository_RetrieveDocumentSet', 'I_Document_Management', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRegistry_DeleteDocumentSet = WsdlOperation('DocumentRegistry_DeleteDocumentSet', 'I_Document_Management', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        UpdateResponder_RestrictedUpdateDocumentSet = WsdlOperation('UpdateResponder_RestrictedUpdateDocumentSet', 'I_Document_Management', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
    I_Document_Management = _I_Document_Management()
    class _I_Document_Management_Insurant:
        def __str__(self): return 'I_Document_Management_Insurant'
        DocumentRegistry_RegistryStoredQuery = WsdlOperation('DocumentRegistry_RegistryStoredQuery', 'I_Document_Management_Insurant', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRepository_ProvideAndRegisterDocumentSet_b = WsdlOperation('DocumentRepository_ProvideAndRegisterDocumentSet-b', 'I_Document_Management_Insurant', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRepository_RetrieveDocumentSet = WsdlOperation('DocumentRepository_RetrieveDocumentSet', 'I_Document_Management_Insurant', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        DocumentRegistry_DeleteDocumentSet = WsdlOperation('DocumentRegistry_DeleteDocumentSet', 'I_Document_Management_Insurant', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
        UpdateResponder_RestrictedUpdateDocumentSet = WsdlOperation('UpdateResponder_RestrictedUpdateDocumentSet', 'I_Document_Management_Insurant', 'XDSDocumentService', ['schemas3.0', 'XDSDocumentService.wsdl'])
    I_Document_Management_Insurant = _I_Document_Management_Insurant()

