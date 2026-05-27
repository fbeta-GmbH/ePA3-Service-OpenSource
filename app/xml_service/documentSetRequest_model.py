from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Union, Any
from collections import OrderedDict, defaultdict
from pyjson5 import load as json5_load
import os
import argparse
from app.runtime_config.constants import DIGA_PROFESSION_OID

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config")

@dataclass
class ValueList:
    Value: List[str] | None

    def __init__(self, Value: str | Union[str, List[str]] | None):
        self.Value = [Value] if isinstance(Value, str) else Value

    @property
    def __dict__(self):
        return OrderedDict({ "_value_1": [ { "Value": v } for v in self.Value ] }) if self.Value is not None else None

@dataclass
class Slot:
    name: str
    ValueList: ValueList

    @property
    def __dict__(self):
        if self.ValueList.Value is None:
            return None
        else:
            return OrderedDict({
                "name": self.name,
                "ValueList": self.ValueList
            })

@dataclass
class LocalizedString:
    value: str | None
    lang: Optional[str] = None
    charset: Optional[str] = None

@dataclass
class Name:
    LocalizedString: List[LocalizedString]

    def __init__(self, LocalizedString: Union[LocalizedString, List[LocalizedString]]):
        self.LocalizedString = LocalizedString if isinstance(LocalizedString, list) else [LocalizedString]

    @property
    def __dict__(self):
        return OrderedDict({ "_value_1": [ { "LocalizedString": v } for v in self.LocalizedString ] }) if self.LocalizedString is not None else None

@dataclass
class Description:
    LocalizedString: List[LocalizedString]

    def __init__(self, LocalizedString: Union[LocalizedString, List[LocalizedString]]):
        self.LocalizedString = LocalizedString if isinstance(LocalizedString, list) else [LocalizedString]

    @property
    def __dict__(self):
        return OrderedDict({ "_value_1": [ { "LocalizedString": v } for v in self.LocalizedString ] }) if self.LocalizedString is not None else None

@dataclass
class ClassificationItem:
    classificationScheme: Optional[str] = None
    classifiedObject: Optional[str] = None
    nodeRepresentation: Optional[str] = None
    objectType: str = "urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:Classification"
    id: Optional[str] = None
    Name: Optional[Name] = None
    Slot: Optional[List[Slot]] = None
    classificationNode: Optional[str] = None

@dataclass
class ExternalIdentifierItem:
    registryObject: str
    identificationScheme: str
    value: str
    id: str
    Name: Name
    objectType: str = "urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:ExternalIdentifier"

@dataclass
class RegistryPackage:
    id: str
    Slot: List[Slot]
    Name: Name
    Description: Description
    Classification: List[ClassificationItem | None]
    ExternalIdentifier: List[ExternalIdentifierItem]
    objectType: str = "urn:oasis:names:tc:ebxml-regrep:ObjectType:RegistryObject:RegistryPackage"

@dataclass
class ExtrinsicObject:
    mimeType: str
    isOpaque: str
    id: str
    Slot: List[Slot]
    Name: Name
    Classification: List[ClassificationItem]
    ExternalIdentifier: List[ExternalIdentifierItem]
    Description: Description
    objectType: str = "urn:uuid:7edca82f-054d-47f2-a032-9b2a5b5186c1"

@dataclass
class AssociationItem:
    associationType: str
    sourceObject: str
    targetObject: str
    id: str

@dataclass
class RegistryObjectList:
    RegistryPackage: RegistryPackage
    ExtrinsicObject: ExtrinsicObject
    Association: List[AssociationItem]

@dataclass
class SubmitObjectsRequest:
    RegistryObjectList: RegistryObjectList

@dataclass
class Include:
    href: str

@dataclass
class Document:
    id: str
    Include: Include

    @property
    def __dict__(self):
        return OrderedDict({
            "id": self.id
        })

@dataclass
class ProvideAndRegisterDocumentSetRequest:
    SubmitObjectsRequest: SubmitObjectsRequest
    Document: Document


def convert_metadata_list_to_dict(data: list[OrderedDict[str, str]]) -> OrderedDict[str, OrderedDict[str, str]]:
    """
    Convert a list of metadata dictionaries to a nested OrderedDict.

    Args:
        data (list[OrderedDict[str, str]]): List of metadata dictionaries.

    Returns:
        OrderedDict[str, OrderedDict[str, str]]: Nested OrderedDict of metadata.
    """
    new_dict = OrderedDict()
    for entry in data:
        name_parts = entry["name"].split(".")
        if entry['name'] == "documentEntry.mimeType":
            continue
        if name_parts[0] not in new_dict:
            new_dict[name_parts[0]] = OrderedDict()
        new_dict[name_parts[0]][name_parts[1]] = entry["value"]
        if 'desc' in entry["value"]:
            del new_dict[name_parts[0]][name_parts[1]]['desc']
    return new_dict

def dict_to_defaultdict(input_data: dict) -> dict | list:
    """
    Convert input data to a defaultdict recursively.

    Args:
        input_data (dict): Input data dictionary.

    Returns:
        dict | list: Defaultdict or list of defaultdicts.
    """
    if isinstance(input_data, dict):
        return defaultdict(lambda: None, {k: dict_to_defaultdict(v) for k, v in input_data.items()})
    elif isinstance(input_data, list):
        return [dict_to_defaultdict(item) for item in input_data]
    else:
        return input_data

def object_to_dict(obj):
    """
    Convert an object to an OrderedDict recursively.

    Args:
        obj: Object to convert.

    Returns:
        OrderedDict: OrderedDict representation of the object.
    """
    if isinstance(obj, list):
        res = [object_to_dict(item) for item in obj if item is not None]
        res = [item for item in res if item is not None]
        return res if len(res) > 0 else None
    elif isinstance(obj, dict):
        res = OrderedDict({k: object_to_dict(v) for k, v in obj.items() if v is not None})
        res = OrderedDict({k: v for k, v in res.items() if v is not None})
        return res if len(res) > 0 else None
    elif hasattr(obj, "__dict__"):
        if vars(obj) is None:
            return None
        res = OrderedDict({k: object_to_dict(v) for k, v in vars(obj).items() if v is not None})
        res = OrderedDict({k: v for k, v in res.items() if v is not None})
        return res if len(res) > 0 else None
    else:
        return obj

def load_fixed_configuration() -> OrderedDict:
    """
    Get fixed data from the configuration file.

    Returns:
        OrderedDict: Fixed data dictionary.
    """
    with open(os.path.join(CONFIG_PATH, "documentSetRequest_fixed_input.json"), "r", encoding="utf-8") as f:
        return json5_load(f, object_pairs_hook=OrderedDict)

def load_ig_configuration() -> OrderedDict:
    """
    Load the appropriate Implementation Guide configuration based on the professionOID in the SMC-B certificate.
    Overrides practiceSettingCode and healthcareFacilityTypeCode from environment variables if set.
    """
    profession_oid = os.environ.get('OID_DIGA', DIGA_PROFESSION_OID)
    is_diga = profession_oid == DIGA_PROFESSION_OID
    config_file = 'documentSetRequest_ig-diga_V_1_1.json' if is_diga else 'documentSetRequest_ig-le_V_1_0.json'
    with open(os.path.join(CONFIG_PATH, config_file), "r", encoding="utf-8") as f:
        result = convert_metadata_list_to_dict(json5_load(f, object_pairs_hook=OrderedDict)['elements'][0]['metadata'])

    # Override practiceSettingCode from env var (doctor's specialty can't be auto-detected)
    practice_setting_override = os.environ.get('PRACTICE_SETTING_CODE')
    if practice_setting_override and 'documentEntry' in result:
        result['documentEntry']['practiceSettingCode']['code'] = practice_setting_override

    # Override healthcareFacilityTypeCode from env var (auto-detected from professionOID)
    healthcare_facility_override = os.environ.get('HEALTHCARE_FACILITY_TYPE_CODE')
    if healthcare_facility_override and 'documentEntry' in result:
        result['documentEntry']['healthcareFacilityTypeCode']['code'] = healthcare_facility_override

    return result

def load_document_set_request_schema(type: str) -> OrderedDict:
    if type == 'user':
        with open(os.path.join(CONFIG_PATH, "documentSetRequest_user_input_schema.json"), "r", encoding="utf-8") as f:
            return json5_load(f, object_pairs_hook=OrderedDict)
    elif type == 'system':
        with open(os.path.join(CONFIG_PATH, "documentSetRequest_schema.json"), "r", encoding="utf-8") as f:
            return json5_load(f, object_pairs_hook=OrderedDict)
    else:
        raise ValueError(f"Unknown type: {type}")