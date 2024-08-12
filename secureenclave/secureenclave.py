#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import shutil
import platformdirs
import os, sys
import subprocess
import invoke
import psutil
import re

from loguru import logger
from pathlib import Path
from io import StringIO
from bullet import YesNo, Input, VerticalPrompt, Bullet, Password

from .gpgagent import GpgAgent
from .gpg import Gpg

__author__ = 'GaPyTools'
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


    def is_card_installed(self):
        try:
            gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
            result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True, hide=True)
            if match := re.search('sec>  ([a-zA-Z0-9\\/]*)', result.stdout): # type: ignore
                self.card_pub = match.group(1)
                logger.debug(f'Found key in card [{self.card_pub}]')
            else:
                logger.debug('Failed to match. No secure key in card')
                logger.debug(result.stdout) # type: ignore
            return True
        except:
            logger.debug('Card failed to be recognized')
            return False


    def __enter__(self):
        self.gpg_agent.start()
        if self.is_card_installed():
            key_list = self.gpg.get_keys()
            logger.debug(key_list)
            if hasattr(self, 'card_pub') and self.card_pub and len(list(filter(lambda x: x.pub == self.card_pub, key_list))) > 0:
                logger.debug(f'key [{self.card_pub}] already in key list')
            else:
                logger.info('A card is installed. Retrieving remote key id from card')
                gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.gpg.getbin())
                invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=True, in_stream=StringIO(__gpg_fetch_key__))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.gpg_agent.stop()

    def key_status(self):
        gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def list_keys(self):
        gpg_cmd = '{} --list-keys --with-keygrip'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def new_key(self):
        prompts = VerticalPrompt([
            Input("Key Owner Full name: "),
            Input("Key Owner Email address: "),
            Input("Key Name: "),
            Password("Key Password: "),
            Password("Confirm Key Password: ")], spacing=0).launch()
        if prompts[3][1] != prompts[4][1]:
            logger.error("Passwords do not match. Try again.")
            return False
        new_key_uid = f'{prompts[0][1]} ({prompts[2][1]}) <{prompts[1][1]}>'
        passphrase = prompts[3][1]
        logger.info("Creating new key")
        gpg_cmd = '{} -q --batch --passphrase {} --quick-generate-key "{}" rsa4096 cert never'.format(self.gpg.getbin(), passphrase, new_key_uid)
        result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        if result.exited != 0: # type:ignore
            logger.error("Could not create the master key properly")
            return False
        new_key = next(iter([x for x in self.gpg.get_keys() if x.uid == new_key_uid]))
        logger.debug(f'New key with fingerprint {new_key.fingerprint}')
        logger.info('New key created. Creating its subkeys')
        for subkey_type in ['sign', 'encrypt', 'auth']:
            gpg_cmd = '{} -q --batch --pinentry-mode=loopback --passphrase {} --quick-add-key "{}" rsa4096 "{}" "2y"'.format(self.gpg.getbin(), passphrase, new_key.fingerprint, subkey_type)
            result = invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
            if result.exited != 0: # type:ignore
                logger.error(f'Could not create {subkey_type} subkey properly')
                return False
        logger.info('Key creation completed. Use "key list" to explore')


    def del_key(self):
        keys = self.gpg.get_keys()
        selected = Bullet('Select which key to delete: ', keys).launch() # type:ignore
        gpg_cmd = '{} -q --batch --delete-secret-key {}'.format(self.gpg.getbin(), selected.fingerprint)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)
        gpg_cmd = '{} -q --batch --delete-key {}'.format(self.gpg.getbin(), selected.fingerprint)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)


    def encrypt(self, input, output):
        key_list = self.gpg.get_keys()
        if len(key_list):
            selected = Bullet('Select which key to delete: ', key_list).launch() # type:ignore
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

