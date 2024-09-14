#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Gonzalo Alvarez

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import time

from loguru import logger
from ykman.device import list_all_devices, scan_devices
from yubikit.core.smartcard import SmartCardConnection


class SmartCard:
    def __init__(self, gpg):
        self.gpg = gpg

    def wait_for_it(self):
        state = None
        card_not_found=False
        while True:
            pids, new_state = scan_devices()
            if new_state != state:
                devices = list_all_devices()
                if devices:
                    logger.debug(devices)
                    if card_not_found:
                        logger.debug('waiting 500 milliseconds for GPG to pick up the card')
                        time.sleep(0.5)
                    return devices
            card_not_found = True
            time.sleep(0.2)

    def list_cards(self):
        return list_all_devices()
