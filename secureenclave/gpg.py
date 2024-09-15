#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2024, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os, sys
import shutil
import invoke
import re

from dataclasses import dataclass
from loguru import logger
from typing import List


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

@dataclass
class GpgKey:
    uid: str
    pub: str
    fingerprint: str
    trust: str

    def __str__(self):
        return self.uid.strip()

    def __len__(self):
        return len(self.uid.strip())

    def __add__(self, other):
        return str(self) + other

    def __radd__(self, other):
        return other + str(self)

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

    def get_keys(self):
        keys : List[GpgKey] = []
        gpg_cmd = '{} --quiet --list-keys'.format(self.getbin())
        output = invoke.run(gpg_cmd, env=self.getenv(), pty=True, hide=True)
        raw = output.stdout # type: ignore
        if 'uid  ' in raw:
            logger.debug('There is at least a uid in the keylist')
            uid = fingerprint = pub = trust = None
            for line in raw.splitlines():
                if match := re.search('fingerprint[ ]*= ([A-F0-9 ]*)', line):
                    fingerprint = match.group(1).replace(" ", "")
                if match := re.search('uid (.*)$', line):
                    uid = match.group(1).strip()
                    if submatch := re.search("(\\[[ a-z]*\\]) (.*)", uid):
                        uid = submatch.group(2).strip()
                        trust = submatch.group(1).replace("[", "").replace("]","").strip()
                if match := re.search('pub [ ]*([a-zA-Z0-9\\/]*)', line):
                    pub = match.group(1)
                if pub and fingerprint and uid and trust:
                    logger.debug(f'Found a full match key uuid {uid} - {pub}')
                    keys.append(GpgKey(uid, pub, fingerprint, trust))
                    pub = fingerprint = uid = trust = None
        return keys


