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

from loguru import logger


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

    def card_edit(self, attribute, value):
        __content__ = __gpg_card_edit__.format(attribute, value)
        gpg_cmd = '{} --quiet --card-edit --expert --batch --display-charset utf-8 --no-tty --command-fd 0'.format(self.getbin())
        invoke.run(gpg_cmd, env=self.getenv(), hide=True, in_stream=StringIO(__content__))

    def card_key_edit(self, key_id, key_number, slot_number):
        __content__ = __gpg_card_key_edit__.format(key_number, slot_number)
        logger.info(__content__)
        gpg_cmd = '{} --expert --batch --display-charset utf-8 --command-fd 0 --edit-key {}'.format(self.getbin(), key_id)
        invoke.run(gpg_cmd, env=self.getenv(), hide=False, in_stream=StringIO(__content__))
