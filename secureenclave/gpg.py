#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys
import shutil
import invoke
import re
from io import StringIO
import urllib.parse

from loguru import logger
from typing import List, Dict, Any, Optional

from secureenclave.datamodel import GpgKey


__gpg_conf__: str = """use-agent
personal-cipher-preferences AES256 AES192 AES CAST5
personal-digest-preferences SHA512 SHA384 SHA256 SHA224
default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
cert-digest-algo SHA512
s2k-digest-algo SHA512
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
"""

__gpg_card_edit__ = """admin
{}
{}
quit
"""

__gpg_card_key_edit__ = """key {}
keytocard
{}
save
"""

# Mappings for GPG --with-colons output
GPG_ALGORITHM_NAME_MAP: Dict[str, str] = {
    "1": "RSA", "2": "RSA-E", "3": "RSA-S", "16": "ELG-E", "17": "DSA",
    "18": "ECC", "19": "ECDSA", "20": "ELG", "21": "PAD", "22": "EDDSA",
    # Add others as needed
}

GPG_VALIDITY_MAP: Dict[str, str] = {
    'o': "unknown validity",
    'i': "invalid",
    'd': "disabled",
    'r': "revoked",
    'e': "expired",
    '-': "validity not indicated",
    'q': "undefined validity",
    'n': "not valid",
    'm': "marginally valid",
    'f': "fully valid",
    'u': "ultimately valid",
    's': "special validity",
    'w': "well-known public key", # GnuPG specific
}

GPG_OWNERTRUST_MAP: Dict[str, str] = {
    '-': "unknown",
    'o': "unknown", # GnuPG specific for "not enough information"
    'q': "undefined",
    'n': "not trusted",
    'm': "marginally trusted",
    'f': "fully trusted",
    'u': "ultimately trusted",
    'e': "expired", # GnuPG specific for expired trust signature
    'r': "revoked", # GnuPG specific for revoked trust signature
}

GPG_CAPABILITY_MAP: Dict[str, str] = {
    'e': "encrypt",
    's': "sign",
    'c': "certify",
    'a': "authenticate",
    't': "set-primary-uid", # GnuPG specific, often on self-signatures
    '?': "unknown"
}


class Gpg(object):
    def __init__(self, homepath):
        self.gpg_bin = shutil.which('gpg')
        if not self.gpg_bin:
            raise Exception('Failed to find gpg program. Use your package manager or homebrew to install it and make sure it is in the path.')
        self.gpg_home = homepath.joinpath('gpg')
        if not self.gpg_home.exists():
            logger.info('Configuration not found. Setting up new configuration')
            self.gpg_home.mkdir(mode=0o700, parents=True, exist_ok=True)
            logger.debug(f"GPG Home folder [{self.gpg_home}]")
            with self.gpg_home.joinpath('gpg.conf').open('w') as conffile:
                conffile.write(__gpg_conf__)
            logger.debug("Configuration written")

    def getenv(self):
        environment = {'SSH_AUTH_SOCK': self.gpg_home.joinpath('S.gpg-agent.ssh').as_posix(),
                       'GNUPGHOME': self.gpg_home.as_posix(), 'GPG_TTY': os.ttyname(sys.stdout.fileno())}
        env = dict(os.environ)
        env.update(environment)
        return env

    def gethome(self):
        return self.gpg_home

    def getbin(self):
        return self.gpg_bin

    def _parse_gpg_list_cmd(self, raw_output: str) -> List[GpgKey]:
        keys_list: List[GpgKey] = []
        current_key_details: Dict[str, Any] = {}

        for line in raw_output.splitlines():
            fields = line.strip().split(':')
            if not fields:
                continue

            record_type = fields[0]

            if record_type == 'pub':
                # Start of a new public key block
                current_key_details = {
                    'key_id': fields[4],
                    'algorithm_name': GPG_ALGORITHM_NAME_MAP.get(fields[3], f"unknown_algo_{fields[3]}"),
                    'key_length': int(fields[2]) if fields[2].isdigit() else 0,
                    'creation_date': int(fields[5]) if fields[5].isdigit() else 0,
                    'expiration_date': int(fields[6]) if fields[6].isdigit() else None,
                    'owner_trust': GPG_OWNERTRUST_MAP.get(fields[8], "unknown") if len(fields) > 8 else "unknown",
                    'capabilities': [],
                    'fingerprint': None, # Will be filled by 'fpr' record
                    'keygrip': None,     # Will be filled by 'grp' record
                }
                # Parse capabilities from field 11 (e.g., "scea")
                if len(fields) > 11 and fields[11]:
                    for char_code in fields[11]:
                        current_key_details['capabilities'].append(GPG_CAPABILITY_MAP.get(char_code, f"unknown_cap_{char_code}"))
                logger.debug(f"Parsing pub key: {current_key_details['key_id']}")

            elif record_type == 'fpr' and current_key_details:
                # Fingerprint for the current key
                if len(fields) > 9:
                    current_key_details['fingerprint'] = fields[9]
                    logger.debug(f"Found fingerprint for {current_key_details.get('key_id')}: {fields[9]}")


            elif record_type == 'grp' and current_key_details:
                # Keygrip for the current key
                if len(fields) > 9:
                    current_key_details['keygrip'] = fields[9]
                    logger.debug(f"Found keygrip for {current_key_details.get('key_id')}: {fields[9]}")

            elif record_type == 'uid' and current_key_details and 'key_id' in current_key_details:
                # User ID for the current key
                uid_string = ""
                if len(fields) > 9: # GnuPG 2.1+ format
                    uid_string = urllib.parse.unquote_plus(fields[9])
                elif len(fields) > 7: # Older GnuPG format might have UID in field 7
                     uid_string = urllib.parse.unquote_plus(fields[7])


                uid_validity_char = fields[1]
                uid_validity = GPG_VALIDITY_MAP.get(uid_validity_char, "unknown validity")

                if not uid_string: # Skip if UID string is empty
                    logger.warning(f"Skipping UID for key {current_key_details['key_id']} due to empty UID string. Line: {line}")
                    continue

                gpg_key = GpgKey(
                    uid=uid_string,
                    key_id=current_key_details['key_id'],
                    fingerprint=current_key_details.get('fingerprint'),
                    uid_validity=uid_validity,
                    owner_trust=current_key_details.get('owner_trust'),
                    algorithm_name=current_key_details['algorithm_name'],
                    key_length=current_key_details['key_length'],
                    creation_date=current_key_details['creation_date'],
                    expiration_date=current_key_details.get('expiration_date'),
                    capabilities=current_key_details.get('capabilities', []),
                    keygrip=current_key_details.get('keygrip')
                )
                keys_list.append(gpg_key)
                logger.debug(f"Added GpgKey: {uid_string} for key {current_key_details['key_id']}")

            elif record_type in ('sub', 'ssb'): # Subkey, reset current_key_details to avoid associating UIDs with subkeys
                # For now, we are not parsing subkeys into GpgKey objects in this list.
                # If subkeys were to be listed, they'd need their own 'fpr', 'grp' etc.
                # Resetting current_key_details ensures subsequent UIDs are not wrongly associated.
                # However, GPG lists UIDs under their primary key, not subkeys.
                # So, this might not be strictly necessary unless the output format changes.
                # For safety, we can clear parts that are subkey-specific if we were to process them.
                # For now, we assume UIDs always belong to the last 'pub' key.
                pass


        if not keys_list and raw_output:
            logger.debug("No keys found or parsed from GPG output.")
        elif not raw_output:
            logger.debug("GPG output was empty.")

        return keys_list

    def get_keys(self) -> List[GpgKey]:
        # Use --with-colons for machine-readable output
        # --fixed-list-mode helps stabilize output across GPG versions
        # --with-fingerprint ensures fingerprints are included
        gpg_cmd = f'{self.getbin()} --with-colons --fixed-list-mode --with-fingerprint --list-keys'
        logger.debug(f"Executing GPG command: {gpg_cmd}")
        try:
            # pty=True is generally not recommended for machine-readable output
            output = invoke.run(gpg_cmd, env=self.getenv(), hide=True, warn=True) # warn=True to catch errors
            output.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            raw: str = output.stdout
            logger.trace(f"Raw GPG output:\n{raw}")
            return self._parse_gpg_list_cmd(raw)
        except invoke.exceptions.UnexpectedExit as e:
            logger.error(f"GPG command failed: {e.result.command}")
            logger.error(f"GPG stderr: {e.result.stderr}")
            logger.error(f"GPG stdout: {e.result.stdout}")
            return [] # Return empty list on error
        except Exception as e:
            logger.error(f"An unexpected error occurred while getting GPG keys: {e}")
            return []


    def card_edit(self, attribute, value):
        __content__ = __gpg_card_edit__.format(attribute, value)
        gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.getbin())
        invoke.run(gpg_cmd, env=self.getenv(), hide=True, in_stream=StringIO(__content__))

    def card_key_edit(self, key_id, key_number, slot_number):
        __content__ = __gpg_card_key_edit__.format(key_number, slot_number)
        gpg_cmd = '{} --expert --batch --display-charset utf-8 --no-tty --command-fd 0 --edit-key {}'.format(self.getbin(), key_id)
        invoke.run(gpg_cmd, env=self.getenv(), hide=True, in_stream=StringIO(__content__))
