#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import sys
import shutil
import invoke
from io import StringIO
import urllib.parse

from loguru import logger
from typing import List, Dict, Any, Optional, Tuple

from secureenclave.datamodel import GpgKey, GpgSubkey


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

GPG_ALGORITHM_NAME_MAP: Dict[str, str] = {
    "1": "RSA", "2": "RSA-E", "3": "RSA-S", "16": "ELG-E", "17": "DSA",
    "18": "ECC", "19": "ECDSA", "20": "ELG", "21": "PAD", "22": "EDDSA",
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
    'w': "well-known public key",
}

GPG_OWNERTRUST_MAP: Dict[str, str] = {
    '-': "unknown",
    'o': "unknown",
    'q': "undefined",
    'n': "not trusted",
    'm': "marginally trusted",
    'f': "fully trusted",
    'u': "ultimately trusted",
    'e': "expired",
    'r': "revoked",
}

GPG_CAPABILITY_MAP: Dict[str, str] = {
    'e': "encrypt",
    's': "sign",
    'c': "certify",
    'a': "authenticate",
    't': "set-primary-uid",
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

    def run_cmd(self, cmd, silent=True, in_stream=None) -> (invoke.Result | None):
        try:
            result = invoke.run(cmd, env=self.getenv(), pty=not silent, hide=silent, in_stream=in_stream)
            return result
        except Exception as e:
            logger.warning('Invocation of GPG command has failed')
            logger.warning(f'CMD: {cmd}')
            logger.warning(f'Exception: {str(e)}')
        return None

    def _parse_gpg_list_cmd(self, raw_output: str) -> List[GpgKey]:
        primary_keys_info: Dict[str, Dict[str, Any]] = {}
        current_pk_id_active: Optional[str] = None
        attachment_target_dict: Optional[Dict[str, Any]] = None

        for line in raw_output.splitlines():
            fields = line.strip().split(':')
            if not fields or len(fields) < 1:
                continue

            record_type = fields[0]

            if record_type in ('pub', 'sec'):
                pk_id = fields[4]
                current_pk_id_active = pk_id
                is_secret_record = (record_type == 'sec' and fields[14] == '+')

                if pk_id not in primary_keys_info:
                    primary_keys_info[pk_id] = {
                        'key_id': pk_id,
                        'algorithm_name': GPG_ALGORITHM_NAME_MAP.get(fields[3], f"unknown_algo_{fields[3]}"),
                        'key_length': int(fields[2]) if fields[2].isdigit() else 0,
                        'creation_date': int(fields[5]) if fields[5].isdigit() else 0,
                        'expiration_date': int(fields[6]) if fields[6].isdigit() else None,
                        'owner_trust': GPG_OWNERTRUST_MAP.get(fields[8], "unknown") if len(fields) > 8 else "unknown",
                        'capabilities': [],
                        'fingerprint': None,
                        'keygrip': None,
                        'secret_available': is_secret_record,
                        'secret_in_card': 'sc' in fields[11],
                        'uids': [],
                        'subkeys': {},
                    }
                elif is_secret_record:
                    primary_keys_info[pk_id]['secret_available'] = True

                if primary_keys_info[pk_id]['secret_in_card']:
                    logger.debug('Secret lives in card')
                    full_card_serial = fields[14].strip()
                    if full_card_serial and len(full_card_serial) == 32 and full_card_serial.startswith("D27600012401"):
                        primary_keys_info[pk_id]['card_serial'] = f'{full_card_serial[16:20]} {full_card_serial[20:28]}'
                        logger.debug(f'Card serial: {primary_keys_info[pk_id]['card_serial']}')
                if not is_secret_record and primary_keys_info[pk_id].get('secret_available', False):
                    pass
                elif is_secret_record:
                    primary_keys_info[pk_id]['secret_available'] = True

                primary_keys_info[pk_id]['algorithm_name'] = GPG_ALGORITHM_NAME_MAP.get(fields[3], f"unknown_algo_{fields[3]}")
                primary_keys_info[pk_id]['key_length'] = int(fields[2]) if fields[2].isdigit() else 0
                primary_keys_info[pk_id]['creation_date'] = int(fields[5]) if fields[5].isdigit() else 0
                primary_keys_info[pk_id]['expiration_date'] = int(fields[6]) if fields[6].isdigit() else None
                primary_keys_info[pk_id]['owner_trust'] = GPG_OWNERTRUST_MAP.get(fields[8], "unknown") if len(fields) > 8 else "unknown"
                pk_entry_ref = primary_keys_info[pk_id]
                pk_entry_ref['capabilities'] = []
                if len(fields) > 11 and fields[11]:
                    for char_code in fields[11]:
                        pk_entry_ref['capabilities'].append(GPG_CAPABILITY_MAP.get(char_code.lower(), f"unknown_cap_{char_code}"))
                attachment_target_dict = pk_entry_ref
                logger.debug(f"Processed {record_type} key: {pk_id}, secret_available: {pk_entry_ref['secret_available']}")

            elif record_type in ('sub', 'ssb'):
                if not current_pk_id_active:
                    logger.warning(f"Orphaned subkey record: {line}. Skipping.")
                    continue
                sk_id = fields[4]
                is_secret_subkey_record = (record_type == 'ssb' and fields[14] == '+')
                pk_entry_ref = primary_keys_info[current_pk_id_active]

                if sk_id not in pk_entry_ref['subkeys']:
                    pk_entry_ref['subkeys'][sk_id] = {
                        'key_id': sk_id,
                        'algorithm_name': GPG_ALGORITHM_NAME_MAP.get(fields[3], f"unknown_algo_{fields[3]}"),
                        'key_length': int(fields[2]) if fields[2].isdigit() else 0,
                        'creation_date': int(fields[5]) if fields[5].isdigit() else 0,
                        'expiration_date': int(fields[6]) if fields[6].isdigit() else None,
                        'capabilities': [],
                        'fingerprint': None,
                        'keygrip': None,
                        'secret_available': is_secret_subkey_record,
                    }
                elif is_secret_subkey_record:
                    pk_entry_ref['subkeys'][sk_id]['secret_available'] = True

                if not is_secret_subkey_record and pk_entry_ref['subkeys'][sk_id].get('secret_available', False):
                    pass
                elif is_secret_subkey_record:
                    pk_entry_ref['subkeys'][sk_id]['secret_available'] = True

                pk_entry_ref['subkeys'][sk_id]['algorithm_name'] = GPG_ALGORITHM_NAME_MAP.get(fields[3], f"unknown_algo_{fields[3]}")
                pk_entry_ref['subkeys'][sk_id]['key_length'] = int(fields[2]) if fields[2].isdigit() else 0
                pk_entry_ref['subkeys'][sk_id]['creation_date'] = int(fields[5]) if fields[5].isdigit() else 0
                pk_entry_ref['subkeys'][sk_id]['expiration_date'] = int(fields[6]) if fields[6].isdigit() else None

                sk_entry_ref = pk_entry_ref['subkeys'][sk_id]
                sk_entry_ref['capabilities'] = []
                if len(fields) > 11 and fields[11]:
                    for char_code in fields[11]:
                        sk_entry_ref['capabilities'].append(GPG_CAPABILITY_MAP.get(char_code.lower(), f"unknown_cap_{char_code}"))
                attachment_target_dict = sk_entry_ref
                logger.debug(f"Processed {record_type} subkey: {sk_id} for pk {current_pk_id_active}, secret_available: {sk_entry_ref['secret_available']}")

            elif record_type == 'fpr':
                if attachment_target_dict and len(fields) > 9:
                    attachment_target_dict['fingerprint'] = fields[9]
                    logger.debug(f"Found fingerprint for {attachment_target_dict.get('key_id')}: {fields[9]}")
                else:
                    logger.warning(f"Orphaned fingerprint or no attachment target: {line}")

            elif record_type == 'grp':
                if attachment_target_dict and len(fields) > 9:
                    attachment_target_dict['keygrip'] = fields[9]
                    logger.debug(f"Found keygrip for {attachment_target_dict.get('key_id')}: {fields[9]}")
                else:
                    logger.warning(f"Orphaned keygrip or no attachment target: {line}")

            elif record_type == 'uid':
                if not current_pk_id_active:
                    logger.warning(f"Orphaned UID record: {line}. Skipping.")
                    continue

                uid_string = urllib.parse.unquote_plus(fields[9]) if len(fields) > 9 else ""
                uid_validity_char = fields[1]
                uid_validity = GPG_VALIDITY_MAP.get(uid_validity_char, "unknown validity")

                if not uid_string:
                    logger.warning(f"Skipping UID for key {current_pk_id_active} due to empty UID string. Line: {line}")
                    continue
                primary_keys_info[current_pk_id_active]['uids'].append({
                    'uid_text': uid_string,
                    'uid_validity': uid_validity,
                })
                attachment_target_dict = primary_keys_info[current_pk_id_active]
                logger.debug(f"Processed UID: '{uid_string}' for pk {current_pk_id_active}")

        final_gpg_keys: List[GpgKey] = []
        for pk_id, pk_data_dict in primary_keys_info.items():
            subkeys_obj_list: List[GpgSubkey] = []
            for sk_id, sk_data_dict in pk_data_dict.get('subkeys', {}).items():
                subkeys_obj_list.append(GpgSubkey(**sk_data_dict))
            if not pk_data_dict.get('uids'):
                logger.warning(f"Primary key {pk_id} has no UIDs. Skipping GpgKey object creation for it directly, though its subkeys are parsed.")
            for uid_info in pk_data_dict.get('uids', []):
                constructor_pk_data = {k: v for k, v in pk_data_dict.items() if k not in ['uids', 'subkeys']}
                gpg_key_obj = GpgKey(
                    uid=uid_info['uid_text'],
                    uid_validity=uid_info['uid_validity'],
                    subkeys=subkeys_obj_list,
                    **constructor_pk_data
                )
                final_gpg_keys.append(gpg_key_obj)
        if not final_gpg_keys and raw_output:
            logger.debug("No GPG keys with UIDs were fully parsed from GPG output.")
        elif not raw_output:
            logger.debug("GPG output was empty.")
        return final_gpg_keys

    def _dedup_keys(self, public_keys: List[GpgKey], secret_keys: List[GpgKey]) -> List[GpgKey]:
        merged_keys_map: Dict[Tuple[str, str], GpgKey] = {}

        for pub_key in public_keys:
            key_tuple = (pub_key.key_id, pub_key.uid)
            merged_keys_map[key_tuple] = pub_key

        for sec_key in secret_keys:
            key_tuple = (sec_key.key_id, sec_key.uid)
            if key_tuple in merged_keys_map:
                existing_key = merged_keys_map[key_tuple]
                existing_key.secret_available = sec_key.secret_available
                existing_key.card_serial = sec_key.card_serial
                existing_subkeys_map: Dict[str, GpgSubkey] = {
                    subkey.key_id: subkey for subkey in existing_key.subkeys
                }

                for sec_subkey in sec_key.subkeys:
                    if sec_subkey.key_id in existing_subkeys_map:
                        existing_subkeys_map[sec_subkey.key_id].secret_available = sec_subkey.secret_available
                    else:
                        existing_key.subkeys.append(sec_subkey)
            else:
                merged_keys_map[key_tuple] = sec_key

        logger.debug(merged_keys_map.values())
        return list(merged_keys_map.values())

    def get_keys(self) -> List[GpgKey]:
        logger.info('Getting the public keys')
        command = f'{self.getbin()} --with-colons --fixed-list-mode --with-fingerprint --list-keys'
        output = invoke.run(command=command, env=self.getenv(), hide=True, warn=True)
        logger.debug(f'Public key output: {output.stdout}')
        public_keys = self._parse_gpg_list_cmd(output.stdout)
        logger.info('Retrieving the secret keys')
        command = f'{self.getbin()} --with-fingerprint --with-keygrip --list-secret-keys'
        output = invoke.run(command=command, env=self.getenv(), hide=True, warn=True)
        logger.debug(f'Secret key output: {output.stdout}')
        command = f'{self.getbin()} --with-colons --fixed-list-mode --with-keygrip --with-fingerprint --list-secret-keys'
        output = invoke.run(command=command, env=self.getenv(), hide=True, warn=True)
        logger.debug(f'Secret key output: {output.stdout}')
        secret_keys = self._parse_gpg_list_cmd(output.stdout)
        keys = self._dedup_keys(public_keys, secret_keys)
        return keys

    def card_edit(self, attribute, value):
        __content__ = __gpg_card_edit__.format(attribute, value)
        gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.getbin())
        invoke.run(gpg_cmd, env=self.getenv(), hide=True, in_stream=StringIO(__content__))

    def card_key_edit(self, key_id, key_number, slot_number):
        __content__ = __gpg_card_key_edit__.format(key_number, slot_number)
        logger.info(__content__)
        gpg_cmd = '{} --expert --batch --display-charset utf-8 --command-fd 0 --edit-key {}'.format(self.getbin(), key_id)
        invoke.run(gpg_cmd, env=self.getenv(), hide=False, in_stream=StringIO(__content__))
