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

    def __str__(self):
        return f"Subkey({self.key_id}, {self.algorithm_name})"


@dataclass
class GpgKey:
    uid: str  # User ID string
    key_id: str  # Primary Key ID
    fingerprint: Optional[str]  # Primary Key fingerprint
    uid_validity: str  # Validity of the UID
    owner_trust: Optional[str]  # Owner trust of the primary key
    algorithm_name: str  # Primary key algorithm
    key_length: int  # Primary key length in bits
    creation_date: int  # Primary key creation date (timestamp)
    expiration_date: Optional[int]  # Primary key expiration date (timestamp)
    capabilities: List[str]  # Primary key capabilities
    keygrip: Optional[str]  # Primary keygrip
    subkeys: List[GpgSubkey] = field(default_factory=list)  # List of associated subkeys

    def __str__(self):
        return f"{self.uid} ({self.key_id})"

    def __len__(self):
        return len(self.uid.strip())

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)
