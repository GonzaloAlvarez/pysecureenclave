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
