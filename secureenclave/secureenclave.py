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

__author__ = 'GaPyTools'
__program__ = 'SecureEnclave'

__gpg_conf__ = """use-agent
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

__gpg_fetch_key__ = """admin
fetch
quit
"""

__gpg_trust_key__ = """trust
5
y
quit
"""

def lookup_executables(exec_names):
    executables = {}
    for exec_name in exec_names:
        executables[exec_name] = shutil.which(exec_name)
        logger.debug(f"Executable [{exec_name}] in [{executables[exec_name]}]")
    return executables


class SecureEnclave(object):

    @staticmethod
    def purge():
        home = Path(platformdirs.user_data_dir(__program__, __author__))
        client = YesNo('Are you sure you want to remove the configuration folder for Secure Enclave and all the stored keys? ', default='n')
        if client.launch():
            shutil.rmtree(home)
            logger.debug('Configuration removed')

    def __init__(self):
        self.execs = lookup_executables(['gpg', 'gpg-agent', 'pinentry-tty', 'gpg-connect-agent'])
        self.home = Path(platformdirs.user_data_dir(__program__, __author__))
        self.gpg_home = self.home.joinpath('gpg')
        if not self.gpg_home.exists():
            logger.info('Configuration not found. Setting up new configuration')
            self.gpg_home.mkdir(mode=0o700, parents=True, exist_ok=True)
            logger.debug(f"GPG Home folder [{self.gpg_home}]")
            with self.gpg_home.joinpath('gpg.conf').open('w') as conffile:
                conffile.write(__gpg_conf__)
            logger.debug("Configuration written")
        self.gpg_agent = GpgAgent(self.gpg_home)


    def _getenv(self):
        environment = {}
        environment['SSH_AUTH_SOCK'] = self.gpg_home.joinpath('S.gpg-agent.ssh').as_posix()
        environment['GNUPGHOME'] = self.gpg_home.as_posix()
        environment['GPG_TTY'] = os.ttyname(sys.stdout.fileno())
        env = dict(os.environ)
        env.update(environment)
        return env

    def is_card_installed(self):
        try:
            gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.execs['gpg'])
            result = invoke.run(gpg_cmd, env=self._getenv(), pty=True, hide=True)
            if match := re.search('sec>  ([a-zA-Z0-9\\/]*)', result.stdout):
                self.card_sec_id = match.group(1)
                logger.debug(f'Found key in card [{self.card_sec_id}]')
            else:
                logger.debug('Failed to match. No secure key in card')
                logger.debug(result.stdout)
            return True
        except:
            logger.debug('Card failed to be recognized')
            return False

    def _get_keylist(self):
        gpg_cmd = '{} --quiet --list-keys'.format(self.execs['gpg'])
        result = invoke.run(gpg_cmd, env=self._getenv(), pty=True, hide=True)
        return result.stdout


    def _get_keys(self):
        keys = {}
        raw = self._get_keylist()
        if 'uid  ' in raw:
            logger.debug('There is at least a uid in the keylist')
            keyid = None
            uid = None
            for line in raw.splitlines():
                if match := re.search('fingerprint[ ]*= ([A-F0-9 ]*)', line):
                    keyid = match.group(1).replace(" ", "")
                if match := re.search('uid (.*)$', line):
                    uid = match.group(1)
                if keyid and uid:
                    logger.debug(f'Found a match key uuid {keyid} - {uid}')
                    keys[keyid] = uid.strip()
                    keyid = uid = None
        return keys


    def __enter__(self):
        self.gpg_agent.start()
        if self.is_card_installed():
            key_list = self._get_keylist()
            if hasattr(self, 'card_sec_id') and self.card_sec_id and self.card_sec_id in key_list:
                logger.debug(f'key [{self.card_sec_id}] already in key list')
            else:
                logger.info('A card is installed. Retrieving remote key id from card')
                gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.execs['gpg'])
                invoke.run(gpg_cmd, env=self._getenv(), hide=True, in_stream=StringIO(__gpg_fetch_key__))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.gpg_agent.stop()

    def key_status(self):
        gpg_cmd = '{} --quiet --batch --card-status --no-tty'.format(self.execs['gpg'])
        invoke.run(gpg_cmd, env=self._getenv(), pty=True)

    def list_keys(self):
        gpg_cmd = '{} --quiet --list-keys'.format(self.execs['gpg'])
        invoke.run(gpg_cmd, env=self._getenv(), pty=True)

    def encrypt(self, input, output):
        key_list = self._get_keys()
        # TODO: Uses the first key for now
        key_id = next(iter(key_list))
        logger.debug(f'Encrypting with keyid [{key_id}]')
        gpg_cmd = '{} --quiet --armor --encrypt --recipient {} -o {} {}'.format(self.execs['gpg'], key_id, output, input)
        invoke.run(gpg_cmd, env=self._getenv(), hide=False, pty=True)

    def _trust_key(self, keyid):
        gpg_cmd = '{} --quiet --expert --batch --display-charset utf-8 --command-fd 0 --no-tty --edit-key {}'.format(self.execs['gpg'], keyid)
        invoke.run(gpg_cmd, env=self._getenv(), hide=True, in_stream=StringIO(__gpg_trust_key__))

    def trust_keys(self):
        key_list = self._get_keys()
        for key,value in key_list.items():
            logger.info(f'Key UID: {value}')
            client = YesNo(f'Would you like to trust [{key}] ', default='n')
            if client.launch():
                self._trust_key(key)

    def decrypt(self, input, output):
        logger.debug('Decrypting with GPG')
        gpg_cmd = '{} --quiet --armor --decrypt -o {} {}'.format(self.execs['gpg'], output, input)
        invoke.run(gpg_cmd, env=self._getenv(), hide=False, pty=True)

