#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2025, Gonzalo Alvarez
# -------------------------------------------------
# Console scripts for key handling
# -------------------------------------------------

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import click
from click_loguru import ClickLoguru
from loguru import logger
from .secureenclave import SecureEnclave
from .cui_keys import ConsoleUI_Keys
from bullet import Bullet, YesNo

__all__ = ['key_list', 'key_del', 'key_new', 'key_trust', 'key_import']

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.command(name='list', help='List keys')
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_list(ctx, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        keys = secure_enclave.key_handler.get_keys()
        if not keys:
            logger.info("No GPG keys found in the keyring.")
            return

        console_ui_keys = ConsoleUI_Keys()
        logger.info("Available GPG Keys:")
        for key in keys:
            console_ui_keys.display_key(key)
        logger.info("───────────────────────────────────────────────────────────────────────────")


@click.command(name='import', help='Import key into keyring')
@click_loguru.init_logger(logfile=False)
@click.argument('input_file', type=click.Path(exists=True))
@click.pass_context
def key_import(ctx, input_file, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        secure_enclave.key_handler.import_key(input_file)


@click.command(name='new', help='New key generation')
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_new(ctx, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        console_ui_keys = ConsoleUI_Keys()
        new_key_uid, passphrase = console_ui_keys.prompt_for_new_key_details(secure_enclave)

        if new_key_uid is not None:
            if not secure_enclave.key_handler.new_key(new_key_uid, passphrase):
                logger.error("Key creation process failed in the backend.")
        else:
            logger.info("Key creation process was cancelled or input was invalid.")


@click.command(name='del', help='Delete Key')
@click_loguru.init_logger(logfile=False)
@click.option('--skip-secret', is_flag=True, default=False, help='Do not delete the secret key')
@click.option('--skip-public', is_flag=True, default=False, help='Do not delete the public key')
@click.pass_context
def key_del(ctx, skip_secret, skip_public, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        keys = secure_enclave.key_handler.get_keys()
        if not keys:
            logger.info("No keys available to delete.")
            return

        selected = Bullet('Select which key to delete: ', keys).launch()  # type:ignore
        if not selected:
            logger.info("Key deletion cancelled.")
            return
        secure_enclave.key_handler.del_key(selected.fingerprint, secret=not skip_secret, public=not skip_public)


@click.command(name='trust', help='Trust a specific key from the list')
@click_loguru.init_logger(logfile=False)
@click.pass_context
def key_trust(ctx, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        key_list = secure_enclave.gpg.get_keys()
        trusted_count = 0
        for key in key_list:
            if key.trust == 'ultimate':
                logger.debug('Key already trusted {key.uid}')
            else:
                trusted_count += 1
                logger.info(f'Key UID: {key.uid}')
                client = YesNo(f'Would you like to trust [{key.fingerprint}] ', default='n')
                if client.launch():
                    secure_enclave.key_handler.trust_key(key.fingerprint)
        if trusted_count == 0:
            logger.info('No untrusted keys to trust')
        secure_enclave.trust_keys()
