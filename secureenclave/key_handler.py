#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from loguru import logger
from bullet import Bullet

__gpg_trust_key__ = """trust
5
y
quit
"""


class KeyHandler(object):
    def __init__(self, gpg):
        self.gpg = gpg

    def import_key(self, filename):
        gpg_cmd = '{} --import {}'.format(self.gpg.getbin(), filename)
        self.gpg(gpg_cmd, silent=False)

    def new_key(self, new_key_uid, passphrase):
        if not new_key_uid:
            logger.error("New key UID not provided.")
            return False

        logger.info(f"Creating new GPG key for UID: {new_key_uid}")
        gpg_cmd = '{} -q --batch --passphrase {} --quick-generate-key "{}" rsa4096 cert never'.format(self.gpg.getbin(), passphrase, new_key_uid)
        result = self.gpg.run_cmd(gpg_cmd, silent=False)
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
            result = self.gpg.run_cmd(gpg_cmd, silent=False)
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
            result_secret = self.gpg.run_cmd(gpg_cmd_secret, silent=True)
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
            result_public = self.gpg.run_cmd(gpg_cmd_public, silent=True)
            if result_public.ok:  # type: ignore
                logger.success(f"Public key for {selected.fingerprint} deleted successfully.")
            else:
                logger.error(f"Failed to delete public key for {selected.fingerprint}.")
                logger.debug(f"Output: {result_public.stdout}")  # type: ignore
                logger.debug(f"Error: {result_public.stderr}")  # type: ignore
        else:
            logger.info(f"Skipping public key deletion for {selected.fingerprint} as per --public flag.")

    def trust_key(self, fingerprint: str):
        gpg_cmd = '{} --quiet --expert --batch --display-charset utf-8 --command-fd 0 --no-tty --edit-key {}'.format(self.gpg.getbin(), fingerprint)
        self.gpg.run_cmd(gpg_cmd, silent=False, in_stream=__gpg_trust_key__)
