#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class CardInfo(object):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    sex: Optional[str] = None
    public_key_url: Optional[str] = None


@dataclass
class CertInfo(object):
    country: Optional[str] = 'US'
    state: Optional[str] = None
    city: Optional[str] = None
    owner: Optional[str] = None
    organizational_unit: Optional[str] = None
    common_name: Optional[str] = None


@dataclass
class ServerInfo(CertInfo):
    country: Optional[str] = 'US'
    state: Optional[str] = None
    city: Optional[str] = None
    owner: Optional[str] = None
    organizational_unit: Optional[str] = None
    common_name: Optional[str] = None
    dns_name: Optional[str] = None
    alt_dns_name: Optional[str] = None


@dataclass
class IdentityInfo(object):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    salutation: Optional[str] = None


from typing import Tuple


@dataclass
class GpgSubkey:
    key_id: str
    algorithm_name: str
    key_length: int
    creation_date: int
    expiration_date: Optional[int]
    capabilities: List[str]
    fingerprint: Optional[str] = None
    keygrip: Optional[str] = None
    secret_available: bool = False

    def __str__(self):
        return f"Subkey({self.key_id}, {self.algorithm_name})"


@dataclass
class GpgKey:
    uid: str
    key_id: str
    fingerprint: Optional[str]
    uid_validity: str
    owner_trust: Optional[str]
    algorithm_name: str
    key_length: int
    creation_date: int
    expiration_date: Optional[int]
    capabilities: List[str]
    keygrip: Optional[str]
    secret_available: bool = False
    secret_in_card: bool = False
    card_serial: Optional[str] = None
    subkeys: List[GpgSubkey] = field(default_factory=list)

    def __str__(self):
        return f"{self.uid} ({self.key_id})"

    def __len__(self):
        return len(self.uid.strip())

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)


@dataclass
class CardKeyDetails:
    key_type: str
    fingerprint: Optional[str] = None
    created: Optional[str] = None


@dataclass
class Card:
    reader: Optional[str] = None
    application_id: Optional[str] = None
    application_type: Optional[str] = None # e.g. OpenPGP
    version: Optional[str] = None
    manufacturer: Optional[str] = None
    serial_number: Optional[str] = None
    cardholder_name: Optional[str] = None
    language_prefs: Optional[str] = None
    sex: Optional[str] = None
    login_data: Optional[str] = None
    url_of_public_key: Optional[str] = None
    private_data_available: Optional[str] = None
    signature_pin_state: Optional[str] = None
    key_attributes_sig: Optional[str] = None
    key_attributes_enc: Optional[str] = None
    key_attributes_auth: Optional[str] = None
    max_pin_lengths_sig: Optional[int] = None
    max_pin_lengths_enc: Optional[int] = None
    max_pin_lengths_auth: Optional[int] = None
    pin_retry_sig: Optional[int] = None
    pin_retry_enc: Optional[int] = None
    pin_retry_admin: Optional[int] = None
    signature_counter: Optional[int] = None
    sig_key: Optional[CardKeyDetails] = None
    enc_key: Optional[CardKeyDetails] = None
    auth_key: Optional[CardKeyDetails] = None
    general_key_info: Optional[str] = None
    ca_fingerprint_1: Optional[str] = None
    ca_fingerprint_2: Optional[str] = None
    ca_fingerprint_3: Optional[str] = None
