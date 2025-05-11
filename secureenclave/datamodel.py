#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from dataclasses import dataclass
from typing import Optional


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


@dataclass
class GpgKey:
    uid: str  # User ID string
    key_id: str  # Key ID
    fingerprint: Optional[str]  # Key fingerprint
    uid_validity: str  # Validity of the UID (e.g., "fully valid")
    owner_trust: Optional[str]  # Owner trust (e.g., "ultimately trusted")
    algorithm_name: str  # Public key algorithm (e.g., "RSA")
    key_length: int  # Key length in bits
    creation_date: int  # Key creation date (timestamp)
    expiration_date: Optional[int]  # Key expiration date (timestamp)
    capabilities: List[str]  # Key capabilities (e.g., ["sign", "encrypt"])
    keygrip: Optional[str]  # Keygrip

    def __str__(self):
        return f"{self.uid} ({self.key_id})"

    def __len__(self):
        # Provides a consistent length representation, perhaps based on UID
        return len(self.uid.strip())

    def __add__(self, other):
        # Concatenation behavior, might need adjustment based on typical use
        return str(self) + other

    def __radd__(self, other):
        # Concatenation behavior, might need adjustment based on typical use
        return other + str(self)
