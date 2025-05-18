#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import shutil
import platformdirs
import invoke

from loguru import logger
from pathlib import Path
from io import StringIO
from bullet import YesNo, Bullet

from .gpg import Gpg
from .gpgagent import GpgAgent
from .smartcard import SmartCard
from .identities import IdentityManager


__author__ = 'Gonzalo Alvarez'
__program__ = 'SecureEnclave'

__gpg_fetch_key__ = """admin
fetch
quit
"""

__gpg_trust_key__ = """trust
5
y
quit
"""


class SecureEnclave(object):
    @staticmethod
    def purge():
        home = Path(platformdirs.user_data_dir(__program__, __author__))
        client = YesNo('Are you sure you want to remove the configuration folder for Secure Enclave and all the stored keys? ', default='n')
        if client.launch():
            shutil.rmtree(home)
            logger.debug('Configuration removed')

    def __init__(self):
        self.home = Path(platformdirs.user_data_dir(__program__, __author__))
        self.gpg = Gpg(self.home)
        self.gpg_agent = GpgAgent(self.gpg)
        self.smartcard = SmartCard(self.gpg)
        self.identity_manager = IdentityManager(self.home)

    def __enter__(self):
        """Enter context manager"""
        self.gpg_agent.start()
        if self.smartcard.is_card_installed():
            key_list = self.gpg.get_keys()
            logger.debug(key_list)
            if hasattr(self, 'card_pub') and self.card_pub and len(list(filter(lambda x: x.pub == self.card_pub, key_list))) > 0:
                logger.debug(f'key [{self.card_pub}] already in key list')
            else:
                logger.info('A card is installed. Retrieving remote key id from card')
                gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.gpg.getbin())
                self.gpg.run_cmd(gpg_cmd, in_stream=StringIO(__gpg_fetch_key__))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager"""
        self.gpg_agent.stop()

    def import_key(self, filename):
        gpg_cmd = '{} --import {}'.format(self.gpg.getbin(), filename)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def new_key(self, new_key_uid, passphrase):
        if not new_key_uid:
            logger.error("New key UID not provided.")
            return False

        logger.info(f"Creating new GPG key for UID: {new_key_uid}")
        gpg_cmd = '{} -q --batch --passphrase {} --quick-generate-key "{}" rsa4096 cert never'.format(self.gpg.getbin(), passphrase, new_key_uid)
        result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        if result.exited != 0:  # type:ignore
            logger.error("Could not create the master GPG key properly.")
            logger.error(f"GPG command output: {result.stdout} {result.stderr}")
            return False

        created_key = None
        for key_attempt in self.gpg.get_keys():
            if new_key_uid in key_attempt.uid:
                created_key = key_attempt
                break

        if not created_key:
            logger.error(f"Failed to find the newly created GPG key with UID part: {new_key_uid}. Please check GPG manually.")
            available_keys_uids = [k.uid for k in self.gpg.get_keys()]
            logger.debug(f"Available key UIDs after creation attempt: {available_keys_uids}")
            return False

        logger.debug(f'New GPG key created with fingerprint {created_key.fingerprint}')
        logger.info('New GPG key created. Proceeding to create its subkeys.')
        for subkey_type in ['sign', 'encrypt', 'auth']:
            logger.info(f"Creating {subkey_type} subkey...")
            gpg_cmd = '{} -q --batch --pinentry-mode=loopback --passphrase {} --quick-add-key "{}" rsa4096 "{}" "2y"'.format(self.gpg.getbin(), passphrase, created_key.fingerprint, subkey_type)
            result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
            if result.exited != 0:  # type:ignore
                logger.error(f'Could not create {subkey_type} subkey properly.')
                logger.error(f"GPG command output: {result.stdout} {result.stderr}")
                return False
            logger.success(f'{subkey_type.capitalize()} subkey created successfully.')
        logger.success('GPG Key creation completed, including all subkeys. Use "key list" to explore.')
        return True

    def del_key(self, public=True, secret=True):
        keys = self.gpg.get_keys()
        if not keys:
            logger.info("No keys available to delete.")
            return

        selected = Bullet('Select which key to delete: ', keys).launch()  # type:ignore
        if not selected:
            logger.info("Key deletion cancelled.")
            return

        if secret:
            gpg_cmd_secret = '{} -q --batch --delete-secret-key {}'.format(self.gpg.getbin(), selected.fingerprint)
            result_secret = invoke.run(gpg_cmd_secret, env=self.gpg.getenv(), pty=True, hide=True)
            if result_secret.ok:  # type: ignore
                logger.success(f"Secret key for {selected.fingerprint} deleted successfully.")
            else:
                logger.error(f"Failed to delete secret key for {selected.fingerprint}.")
                logger.debug(f"Output: {result_secret.stdout}")  # type: ignore
                logger.debug(f"Error: {result_secret.stderr}")  # type: ignore
        else:
            logger.info(f"Skipping secret key deletion for {selected.fingerprint} as per --secret flag.")

        if public:
            logger.info(f"Attempting to delete public key for {selected.fingerprint}...")
            gpg_cmd_public = '{} -q --batch --delete-key {}'.format(self.gpg.getbin(), selected.fingerprint)
            result_public = invoke.run(gpg_cmd_public, env=self.gpg.getenv(), pty=True, hide=True)
            if result_public.ok:  # type: ignore
                logger.success(f"Public key for {selected.fingerprint} deleted successfully.")
            else:
                logger.error(f"Failed to delete public key for {selected.fingerprint}.")
                logger.debug(f"Output: {result_public.stdout}")  # type: ignore
                logger.debug(f"Error: {result_public.stderr}")  # type: ignore
        else:
            logger.info(f"Skipping public key deletion for {selected.fingerprint} as per --secret flag.")

    def encrypt(self, input, output):
        key_list = self.gpg.get_keys()
        if len(key_list):
            selected = Bullet('Select which key to delete: ', key_list).launch()  # type:ignore
            key_id = selected.fingerprint
            logger.debug(f'Encrypting with keyid [{key_id}]')
            gpg_cmd = '{} --quiet --armor --encrypt --recipient {} -o {} {}'.format(self.gpg.getbin(), key_id, output, input)
            invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)

    def trust_keys(self):
        key_list = self.gpg.get_keys()
        logger.debug(len(key_list))
        logger.debug(key_list)
        trusted_count = 0
        for key in key_list:
            if key.trust == 'ultimate':
                logger.debug('Key already trusted {key.uid}')
            else:
                trusted_count += 1
                logger.info(f'Key UID: {key.uid}')
                client = YesNo(f'Would you like to trust [{key.fingerprint}] ', default='n')
                if client.launch():
                    gpg_cmd = '{} --quiet --expert --batch --display-charset utf-8 --command-fd 0 --no-tty --edit-key {}'.format(self.gpg.getbin(), key.fingerprint)
                    invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=True, in_stream=StringIO(__gpg_trust_key__))
        if trusted_count == 0:
            logger.info('No untrusted keys to trust')

    def decrypt(self, input, output):
        logger.debug('Decrypting with GPG')
        gpg_cmd = '{} --quiet --armor --decrypt -o {} {}'.format(self.gpg.getbin(), output, input)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)
