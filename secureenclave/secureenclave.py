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
from bullet import YesNo

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
        gpg_cmd = '{} --quiet --list-keys'.format(self.gpg.getbin())
        invoke.run(gpg_cmd, env=self.gpg.getenv(), pty=True)

    def encrypt(self, input, output):
        key_list = self.gpg.get_keys()
        if len(key_list):
            # TODO: Uses the first key for now
            key_id = key_list[0].fingerprint
            logger.debug(f'Encrypting with keyid [{key_id}]')
            gpg_cmd = '{} --quiet --armor --encrypt --recipient {} -o {} {}'.format(self.gpg.getbin(), key_id, output, input)
            invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)

    def _trust_key(self, keyid):
        gpg_cmd = '{} --quiet --expert --batch --display-charset utf-8 --command-fd 0 --no-tty --edit-key {}'.format(self.gpg.getbin(), keyid)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=True, in_stream=StringIO(__gpg_trust_key__))

    def trust_keys(self):
        key_list = self.gpg.get_keys()
        logger.debug(len(key_list))
        logger.debug(key_list)
        for key in key_list:
            if key.trust == 'ultimate':
                logger.debug('Key already trusted {key.uid}')
            else:
                logger.info(f'Key UID: {key.uid}')
                client = YesNo(f'Would you like to trust [{key.fingerprint}] ', default='n')
                if client.launch():
                    self._trust_key(key.fingerprint)

    def decrypt(self, input, output):
        logger.debug('Decrypting with GPG')
        gpg_cmd = '{} --quiet --armor --decrypt -o {} {}'.format(self.gpg.getbin(), output, input)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)

