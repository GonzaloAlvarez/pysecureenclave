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
from secureenclave.secureenclave import SecureEnclave


__all__ = ['store_new']

__program__ = 'secureenclave'
__version__ = '0.0.1'

log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>\n"
click_loguru = ClickLoguru(__program__, __version__, stderr_format_func=lambda x: log_format)


@click.command(name='new', help='New Store')
@click_loguru.init_logger(logfile=False)
@click.pass_context
def store_new(ctx, **kwargs):
    with SecureEnclave(base_path=ctx.obj.base_path) as secure_enclave:
        secure_enclave.store_handler.new_store()
