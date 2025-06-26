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
from bullet import YesNo, Bullet

from .gpg import Gpg
from .gpgagent import GpgAgent
from .smartcard import SmartCard
from .identities import IdentityManager
from .key_handler import KeyHandler
from .store_manager import StoreManager


__author__ = 'Gonzalo Alvarez'
__program__ = 'SecureEnclave'


class SecureEnclave(object):
    @staticmethod
    def purge():
        home = Path(platformdirs.user_data_dir(__program__, __author__))
        client = YesNo('Are you sure you want to remove the configuration folder for Secure Enclave and all the stored keys? ', default='n')
        if client.launch():
            shutil.rmtree(home)
            logger.debug('Configuration removed')

    def __init__(self, base_path=None):
        if base_path is None:
            self.home = Path(platformdirs.user_data_dir(__program__, __author__))
        else:
            if not Path(base_path).exists() and Path(base_path).is_dir():
                Path(base_path).mkdir(parents=True, exist_ok=True)
            self.home = Path(base_path)
        logger.debug(f'Base path {self.home}')
        self.gpg = Gpg(self.home)
        self.gpg_agent = GpgAgent(self.gpg)
        self.smartcard = SmartCard(self.gpg)
        self.identity_manager = IdentityManager(self.home)
        self.key_handler = KeyHandler(self.gpg)
        self.store_manager = StoreManager(self.home)

    def __enter__(self):
        """Enter context manager"""
        self.gpg_agent.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context manager"""
        self.gpg_agent.stop()

    def decrypt(self, input, output):
        logger.debug('Decrypting with GPG')
        gpg_cmd = '{} --quiet --armor --decrypt -o {} {}'.format(self.gpg.getbin(), output, input)
        invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)

    def encrypt(self, input, output):
        key_list = self.gpg.get_keys()
        if len(key_list):
            selected = Bullet('Select which key to delete: ', key_list).launch()  # type:ignore
            key_id = selected.fingerprint
            logger.debug(f'Encrypting with keyid [{key_id}]')
            gpg_cmd = '{} --quiet --armor --encrypt --recipient {} -o {} {}'.format(self.gpg.getbin(), key_id, output, input)
            invoke.run(gpg_cmd, env=self.gpg.getenv(), hide=False, pty=True)
